#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>


/* ARP Header, (assuming Ethernet+IPv4)            */ 
// #define ARP_REQUEST 1   /* ARP Request             */ 
// #define ARP_REPLY 2     /* ARP Reply               */ 
// typedef struct arphdr { 
//     u_int16_t htype;    /* Hardware Type           */ 
//     u_int16_t ptype;    /* Protocol Type           */ 
//     u_char hlen;        /* Hardware Address Length */ 
//     u_char plen;        /* Protocol Address Length */ 
//     u_int16_t oper;     /* Operation Code          */ 
//     u_char sha[6];      /* Sender hardware address */ 
//     u_char spa[4];      /* Sender IP address       */ 
//     u_char tha[6];      /* Target hardware address */ 
//     u_char tpa[4];      /* Target IP address       */ 
// }arphdr;
typedef struct arp_content {
	u_char ar_sha[6];      /* Sender hardware address */ 
    u_char ar_sip[4];      /* Sender IP address       */ 
    u_char ar_tha[6];      /* Target hardware address */ 
    u_char ar_tip[4];      /* Target IP address       */ 
}arp_content;

void parseArgs(int argc, char *argv[], char** interface, char** fichier, char** filtre, int* verbosite);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printEthernet(struct ether_header* ethernet, int verbosite);
void printIp(struct iphdr* ip, int verbosite);
void printArp(struct arphdr* arp, int verbosite);
void printTcp(struct tcphdr* tcp, int verbosite);
void printUdp(struct udphdr* udp, int verbosite);
void printDump(u_char *packet, int length);

