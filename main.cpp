#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <arpa/inet.h>
#include "pcap_test.h"

struct ETH eth;
struct IP ip;
struct TCP tcp;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t *mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(uint8_t *ip){
    printf("%d.%d.%d.%d\n",ip[0],ip[1],ip[2],ip[3]);
}

void print_port(uint16_t port){
    printf("%d\n", port);
}

void set_eth(struct ETH *eth,const u_char *packet){
    memcpy(eth,packet,14);

    printf("D-Mac : ");
    print_mac(eth->D_Mac);

    printf("S-Mac : ");
    print_mac(eth->S_Mac);
}

void set_ip(struct IP *ip, const u_char *packet){
    uint8_t len;

    memcpy(ip,packet+14,20);

    len = (ip->VER_IHL & 0xf) * 4;

    printf("S-IP : ");
    print_ip(ip->S_IP);

    printf("D-IP : ");
    print_ip(ip->D_IP);

    if(len > 20){
        ip->Options = (uint8_t *) packet + 14 + 20;
    }
    else{
        ip->Options = 0;
    }
}

void set_tcp(struct TCP *tcp, const u_char *packet){
    memcpy(tcp,packet + 14 + (ip.VER_IHL & 0xf) * 4, 20);


    printf("S-Port : ");
    print_port(htons(tcp->S_Port));
    printf("D-Port : ");
    print_port(htons(tcp->D_Port));

    tcp->Options = (uint8_t *) packet + sizeof(struct ETH) + (ip.VER_IHL & 0xf) * 4 + 20;
}

void print_data(const u_char *packet,unsigned int len){
    unsigned int header_len;

    header_len = 14 + (ip.VER_IHL & 0xf) * 4 + (htons(tcp.Flags) >> 12) * 4;

    if(header_len < len){
        if(len - header_len > 10){
            for(int i = 0; i < 10; i++)
                printf("%x ",packet[header_len+i]);
        }
        else{
            for(int i = 0; i < len - header_len; i++)
                printf("%x ",packet[header_len+i]);
        }
        puts("");
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

    set_eth(&eth,packet);
    if(htons(eth.EType) == 0x800){
        set_ip(&ip,packet);
        if(ip.Protocol == 6){
            set_tcp(&tcp,packet);
            print_data(packet, header->caplen);
        }
    }
    puts("");
  }


  pcap_close(handle);
  return 0;
}
