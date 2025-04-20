#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include "capture.h"
#include "shared.h"

static pcap_t* global_handle = NULL;
static int capture_filter = 0; // 0 = ALL, 1 = TCP only, 2 = UDP only
static int capturing = 1;

void set_capture_filter(int filter_type) {
    capture_filter = filter_type;
}

void stop_capture() {
    capturing = 0;
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    if (!capturing) return;

    struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    int src_port = 0, dst_port = 0;
    char proto[8] = "OTHER";
    if (ip_header->ip_p == IPPROTO_TCP) {
        if (capture_filter == 2) return; // skip if filtering for UDP
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
        strcpy(proto, "TCP");
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        if (capture_filter == 1) return; // skip if filtering for TCP
        struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
        strcpy(proto, "UDP");
    } else {
        if (capture_filter != 0) return; // only show non-TCP/UDP when ALL selected
    }

    char* formatted = malloc(256);
    snprintf(formatted, 256, "%s|%s:%d -> %s:%d", proto, src_ip, src_port, dst_ip, dst_port);
    g_async_queue_push(packet_queue, formatted);
}

void* capture_thread(void* arg) {
    const char* interface = (const char*)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    global_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!global_handle) exit(1);
    pcap_loop(global_handle, -1, packet_handler, NULL);
    pcap_close(global_handle);
    return NULL;
}
