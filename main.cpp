#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(struct in_addr ip) {
    printf("%s\n", inet_ntoa(ip));
}

void print_port(uint16_t port) {
    printf("%u\n", htons(port));
}

void print_data(const u_char* data, size_t len) {
    for(size_t i = 0; i < len; i++)
        printf("%02X ", data[i]);
    printf("\n");
}

void set_packet(const u_char* p) {
    const struct libnet_ethernet_hdr* ether_hdr = reinterpret_cast<const libnet_ethernet_hdr*>(p);
    printf("Dmac: ");
    print_mac(ether_hdr->ether_dhost);
    printf("Smac: ");
    print_mac(ether_hdr->ether_shost);

    if(ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
        const struct libnet_ipv4_hdr* ip_hdr = reinterpret_cast<const struct libnet_ipv4_hdr*>(p + sizeof(struct libnet_ethernet_hdr));
        printf("Sip: ");
        print_ip(ip_hdr->ip_src);
        printf("Dip: ");
        print_ip(ip_hdr->ip_dst);
        p += sizeof(struct libnet_ethernet_hdr);

        if(ip_hdr->ip_p == IPPROTO_TCP) {
            const struct libnet_tcp_hdr* tcp_hdr = reinterpret_cast<const struct libnet_tcp_hdr*>(p + ip_hdr->ip_hl * 4);
            printf("Sport: ");
            print_port(tcp_hdr->th_sport);
            printf("Dport: ");
            print_port(tcp_hdr->th_dport);
            p += ip_hdr->ip_hl * 4;

            const uint8_t* data = reinterpret_cast<const uint8_t*>(p + tcp_hdr->th_off * 4);
            size_t data_length = ntohs(ip_hdr->ip_len) - (tcp_hdr->th_off * 4) - (ip_hdr->ip_hl * 4);
            if(data_length > 10) data_length = 10;
            if (data_length != 0) {
                printf("Data: ");
                print_data(data, data_length);
            }
        }
    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    set_packet(packet);
  }

  pcap_close(handle);
  return 0;
}
