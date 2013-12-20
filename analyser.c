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
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

// struct sniff_ethernet {
// u_char ether_dhost[ETHER_ADDR_LEN]; /*Destination host address*/
// u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
// u_short ether_type; /* IP? ARP? RARP? etc */
// }; 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("Packet recieved : [%d]\n", header->len);
	const struct ether_header *ethernet;
	int size_ethernet = sizeof(struct ether_header);
	ethernet = (struct ether_header*)(packet);
	printf("Ethernet size : [%i]\n", size_ethernet);
	printf("Destination host address : ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    ntohs ((unsigned)ethernet->ether_dhost[0]),//ntohs sur la globalité
    ntohs ((unsigned)ethernet->ether_dhost[1]),
    ntohs ((unsigned)ethernet->ether_dhost[2]),
    ntohs ((unsigned)ethernet->ether_dhost[3]),
    ntohs ((unsigned)ethernet->ether_dhost[4]),
    ntohs ((unsigned)ethernet->ether_dhost[5]));
    printf("Source host address : ");
	printf("%x:%x:%x:%x:%x:%x\n",
    ntohs ((unsigned)ethernet->ether_shost[0]),
    ntohs ((unsigned)ethernet->ether_shost[1]),
    ntohs ((unsigned)ethernet->ether_shost[2]),
    ntohs ((unsigned)ethernet->ether_shost[3]),
    ntohs ((unsigned)ethernet->ether_shost[4]),
    ntohs ((unsigned)ethernet->ether_shost[5]));
    printf("%x\n",ntohs(ethernet->ether_shost));
	//printf("Content : [%s]\n", ethernet->ether_shost);
	printf("Ether_type : [%i]\n", ethernet->ether_type);
};
void parseCommand(int argc, char *argv[], char* interface2, char* fichier, char* filtre, int verbosite){
	printf("Parsing\n");
};
int main(int argc, char *argv[])
{
	// -i <interface> : interface pour l’analyse live
	// -o <fichier> : fichier d’entrée pour l’analyse offline
	// -f <filtre> : filtre BPF (optionnel)
	// -v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)
	char *interface2;
	char *fichier;
	char *filtre;
	int verbosite;

	while ((c = getopt (argc, argv, "iofv:")) != -1)
         switch (c)
           {
           case 'i':
             interface2 = optarg;
             break;
           case 'o':
             bflag = 1;
             break;
           case 'f':
             cvalue = optarg;
             break;
           case 'v':
             cvalue = optarg;
             break;           
           default:
             printf("Arguments missing\n");
           }

	//parseCommand( argc, argv, &interface2, &fichier, &filtre, &verbosite);

	char *interface, errbuf[ BUFFER_SIZE ];
	pcap_t *handle;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	interface = pcap_lookupdev(errbuf);
	if (interface == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", interface);

	if (pcap_lookupnet("eth1"/*interface*/, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
			net = 0;
			mask = 0;
	}

	 handle = pcap_open_live("eth1"/*interface*/, BUFSIZ, 1, 1000, errbuf);
	 if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		 return(2);
	 }
	 printf("Waiting for packets\n");

	//  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	// 		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	// 		return(2);
	// }
	 pcap_loop(handle, 1, got_packet, NULL);
	 // packet = pcap_next(handle, &header);
	 // printf("Jacked a packet with length of [%d]\n", header.len);
	 

	 pcap_close(handle);

	return 0;
}
