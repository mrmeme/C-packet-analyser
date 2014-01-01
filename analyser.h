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
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include "bootp.h"

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