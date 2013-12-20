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
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

void parseArgs(int argc, char *argv[], char** interface, char** fichier, char** filtre, int* verbosite);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printEthernet(struct ether_header* ethernet, int verbosite);