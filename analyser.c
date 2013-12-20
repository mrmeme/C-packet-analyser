#include "analyser.h"

#define BUFFER_SIZE 1024

// struct sniff_ethernet {
// u_char ether_dhost[ETHER_ADDR_LEN]; /*Destination host address*/
// u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
// u_short ether_type; /* IP? ARP? RARP? etc */
// }; 

int main(int argc, char *argv[])
{
	// -i <interface> : interface pour l’analyse live
	// -o <fichier> : fichier d’entrée pour l’analyse offline
	// -f <filtre> : filtre BPF (optionnel)
	// -v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)
	char *interface = NULL;
	char *fichier = NULL;
	char *filtre = NULL;
	int verbosite = 0;
	
	parseArgs( argc, argv, &interface, &fichier, &filtre, &verbosite);	

	char errbuf[ BUFFER_SIZE ];
	pcap_t *handle;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	if (interface == NULL) {
		interface = pcap_lookupdev(errbuf);
			if (interface == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
	}
	printf("Device: %s\n", interface);

	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
			net = 0;
			mask = 0;
	}

	 handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	 if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		 return(2);
	 }

	 printf("Waiting for packets...\n");

	//  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	// 		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	// 		return(2);
	// }
	 pcap_loop(handle, 1, got_packet, &verbosite);
	 // packet = pcap_next(handle, &header);
	 // printf("Jacked a packet with length of [%d]\n", header.len);	 

	 pcap_close(handle);

	return 0;
}

void parseArgs(int argc, char *argv[], char** interface, char** fichier, char** filtre, int* verbosite){
	printf("Parsing Arguments\n");
	int c;
	while ((c = getopt (argc, argv, "i:o:f:v:")) != -1)
         switch (c)
           {
           case 'i':
             *interface = optarg;
             printf("Interface = %s\n", optarg);
             break;
           case 'o':
             *fichier = optarg;
             printf("Fichier = %s\n", optarg);
             break;
           case 'f':
             *filtre = optarg;
             printf("Filtre = %s\n", optarg);
             break;
           case 'v':
             *verbosite = atoi(optarg);
             printf("Verbosite = %d\n", atoi(optarg));
             break;           
           default:
             printf("Arguments missing\n");
           }
    printf("End of parsing\n");
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("Packet recieved : [%d]\n", header->len);
	struct ether_header *ethernet;
	int size_ethernet = sizeof(struct ether_header);
	ethernet = (struct ether_header*)(packet);
	int *verbosite = (int *) args;
	printEthernet(ethernet, *verbosite );
	if (ntohs (ethernet->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(ethernet->ether_type),
                ntohs(ethernet->ether_type));
    }
    struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
    
    u_int hlen,off,version;
    int i;

    int len;
    len     = ntohs(ip->ip_len);
    // hlen    = IP_HL(ip); /* header length */
    // version = IP_V(ip);/* ip version */

    // /* check version */
    // if(version != 4)
    // {
    //   fprintf(stdout,"Unknown version %d\n",version);
    //   return NULL;
    // }

    // /* check header length */
    // if(hlen < 5 )
    // {
    //     fprintf(stdout,"bad-hlen %d \n",hlen);
    // }

    /* see if we have as much packet as we should */
    // if(length < len)
    //     printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    //if((off &apm; 0x1fff) == 0 )/* aka no 1's in first 13 bits */
   // {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                /*hlen,version,*/len,off);
  //  }
	//printf("Ethernet size : %i\n", size_ethernet);	
};

void printEthernet(struct ether_header* ethernet, int verbosite)
{
	printf("Verbosite : %d\n", verbosite);
	printf("Destination host address : ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
     ((unsigned)ethernet->ether_dhost[0]),//ntohs sur la globalité
     ((unsigned)ethernet->ether_dhost[1]),
     ((unsigned)ethernet->ether_dhost[2]),
     ((unsigned)ethernet->ether_dhost[3]),
     ((unsigned)ethernet->ether_dhost[4]),
     ((unsigned)ethernet->ether_dhost[5]));
    printf("Source host address : ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
     ((unsigned)ethernet->ether_shost[0]),
     ((unsigned)ethernet->ether_shost[1]),
     ((unsigned)ethernet->ether_shost[2]),
     ((unsigned)ethernet->ether_shost[3]),
     ((unsigned)ethernet->ether_shost[4]),
     ((unsigned)ethernet->ether_shost[5]));
    //printf("%x\n",ntohs(ethernet->ether_shost));
	//printf("Content : [%s]\n", ethernet->ether_shost);
	printf("Ether_type : [%i]\n", ethernet->ether_type);
};
