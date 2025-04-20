#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "capture.h"

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth_header = (struct ether_header*)packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("[Skipped] Not an IP packet\n");
        return;
    }

    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("[Packet Captured]\n");
    printf("  Length: %d bytes\n", header->len);
    printf("  Timestamp: %s", ctime((const time_t*)&header->ts.tv_sec));
    printf("  Source IP: %s\n", src_ip);
    printf("  Destination IP: %s\n", dst_ip);

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        printf("  Protocol: TCP\n");
        printf("  Source Port: %d\n", ntohs(tcp_header->source));
        printf("  Destination Port: %d\n", ntohs(tcp_header->dest));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        printf("  Protocol: UDP\n");
        printf("  Source Port: %d\n", ntohs(udp_header->source));
        printf("  Destination Port: %d\n", ntohs(udp_header->dest));
    } else {
        printf("  Protocol: Other (%d)\n", ip_header->ip_p);
    }

    printf("-----------------------------\n");
}

void start_capture(const char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // open the interface for live capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Started capturing on interface: %s\n", interface);

    // capture packets until manually stopped
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
}