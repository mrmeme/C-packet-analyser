#include <stdio.h> 
#include <stdlib.h> 
#include <signal.h> 
#include <ctype.h> 
#include <errno.h> 
#include <string.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/telnet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include "bootp.h"

#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_SOA 6
#define DNS_MX 15
#define DNS_AAAA 28

#define DNS_IN 1
#define DNS_ANY 255

struct dns_header{
	unsigned short id;
	unsigned short flags;
	unsigned short qd;
	unsigned short an;
	unsigned short ns;
	unsigned short ar;
};

struct dns_answer{
	unsigned short name;
	unsigned short type;
	unsigned short classe;
	unsigned short _ttl;
	unsigned short ttl;
	unsigned short length;
};

void parseArgs(int argc, char *argv[], char** interface, char** fichier, char** filtre, int* verbosite);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printEthernet(struct ether_header* ethernet, int verbosite);
void printIp(struct iphdr* ip, int verbosite);
void printArp(struct arphdr* arp, int verbosite);
void printTcp(struct tcphdr* tcp, int verbosite);
void printUdp(struct udphdr* udp, int verbosite);
void printBootp(struct bootp* bp, int verbosite);
void printAscii(u_char *packet, int length);
void printDump(u_char *packet, int length);
void printHttp(u_char *data, int datasize, int verbosite); 
void printDns(u_char *data, int verbosite, int type); 
void printTelnet(u_char *packet, int length, int verbosite);