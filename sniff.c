#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;

    // TCP 프로토콜만 필터링
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

    if (ip->protocol != IPPROTO_TCP) return;

    // IP 주소 파싱
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = ip->saddr;
    dst_ip.s_addr = ip->daddr;

    // IP header 길이 (ihl는 4바이트 단위)
    int ip_header_len = ip->ihl * 4;

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);
    int tcp_header_len = tcp->doff * 4;

    // 출력
    printf("Ethernet Header:\n");
    printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    printf("IP Header:\n");
    printf("  Source IP: %s\n", inet_ntoa(src_ip));
    printf("  Destination IP: %s\n", inet_ntoa(dst_ip));

    printf("TCP Header:\n");
    printf("  Source Port: %u\n", ntohs(tcp->source));
    printf("  Destination Port: %u\n", ntohs(tcp->dest));

    printf("------------------------------------------------------\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        fprintf(stderr, "Device not found: %s\n", errbuf);
        return 1;
    }

    printf("Using device: %s\n", dev);

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_loop(handle, 10, packet_handler, NULL); // TCP 패킷 10개만

    pcap_close(handle);
    return 0;
}
