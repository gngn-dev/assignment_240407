/*
	author: rabbit_dev@WHS
	compile option: gcc -o my_tcp_sniffer my_tcp_sniffer.c -lpcap
*/

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "my_header.h"

#define MAX_BYTE_TO_PRINT 100

void print_mac_addr(u_char* data)
{
	for(int i = 0; i < sizeof(data); i++)
	{
		if(i != 0) { printf(":"); }
		printf("%02x", data[i]);
	}
}

void print_msg_to_ascii(const u_char* msg, int msg_length, int max_length){
	int read_length = 0;
	int stop_cnt = 0;
	int i = 0;

	if ( msg_length > max_length ) { read_length = max_length; }
	else { read_length = msg_length; }

	while(stop_cnt < read_length && i < read_length)
	{
		if (i % 32 == 0) { printf("\n"); }

		if (32 <= msg[i] && msg[i] <= 126) { printf("%c", msg[i]); stop_cnt += 1; }
		else { printf("."); }

		i++;
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol == IPPROTO_TCP)
    {
        int ip_header_len = ip->iph_ihl * 4;

        struct tcpheader* tcp = (struct tcpheader *) ((u_char *)ip + ip_header_len);

        printf("\n##### ##### [NEW TCP PACKET] ##### #####\n");

        printf("[Ethernet Header] Source Host: ");
        print_mac_addr(eth->ether_shost);
        printf("\n");
        printf("[Ethernet Header] Destination Host: ");
        print_mac_addr(eth->ether_dhost);
        printf("\n");
        printf("[IP Header] Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("[IP Header] Destination IP: %s\n", inet_ntoa(ip->iph_destip));
        printf("[TCP Header] Source PORT: %d\n", ntohs(tcp->tcp_sport));
        printf("[TCP Header] Destination PORT: %d\n", ntohs(tcp->tcp_dport));
        printf("[TCP Message start]");

        int tcp_header_size = TH_OFF(tcp) * 4;

        const u_char *data = packet + sizeof(struct ethheader) + ip->iph_ihl*4 + tcp_header_size;

        int data_size = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - tcp_header_size;

        print_msg_to_ascii(data, data_size, MAX_BYTE_TO_PRINT);
        printf("\n[TCP Message end]\n");
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    
    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);   //Close the handle

    return 0;
}