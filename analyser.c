#include "analyser.h"

#define BUFFER_SIZE 1024

// struct sniff_ethernet {
// u_char ether_dhost[ETHER_ADDR_LEN]; /*Destination host address*/
// u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
// u_short ether_type; /* IP? ARP? RARP? etc */
// }; 

pcap_t *handle;

void ctrl_c(int n){
    printf("\nFermeture du sniffer\n");
    pcap_close(handle);
    exit(0);
}

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
    struct bpf_program fp;
	//pcap_t *handle;
	// struct pcap_pkthdr header;	 The header that pcap gives us 
	// const u_char *packet;		/* The actual packet */
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

   if(fichier==NULL){
       handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
       if (handle == NULL) {
           fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
           return(2);
       }
    }
    else{
       handle = pcap_open_offline(fichier, errbuf);
       if (handle == NULL) {
           fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
           return(2);
       }
   }
   printf("Waiting for packets...\n");

	if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filtre, pcap_geterr(handle));
			return(2);
	}

    if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't set filter %s: %s\n", filtre, pcap_geterr(handle));
            return(2);
    }
    signal(SIGINT,ctrl_c);
    pcap_loop(handle, -1, got_packet, (u_char *) &verbosite);
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
    printf("********************Paquet recu [%d]********************\n", header->len);
    //printAscii(packet, header->len);
    struct ether_header *ethernet;
    //int size_ethernet = sizeof(struct ether_header);
    ethernet = (struct ether_header*)(packet);
    int *verbosite = (int *) args;
    printEthernet(ethernet, *verbosite );
    struct iphdr *ip;
    struct arphdr *arp;
    struct tcphdr *tcp;
    struct udphdr *udp;
    switch(ntohs(ethernet->ether_type)){
        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
        ip = (struct iphdr*)(packet + sizeof(struct ether_header));
        printIp(ip, *verbosite );
        switch(ip->protocol){
            case IPPROTO_TCP:
            tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip->ihl*4); 
            printTcp(tcp, *verbosite );                       
            break;
            case IPPROTO_UDP:
            udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip->ihl*4); 
            printUdp(udp, *verbosite ); 
            break;
            default:
            printf("Protocol not handled : %d\n",ip->protocol);
            break;
        }
        break;
        // case ETHERTYPE_IPV6:
        // ip = (struct iphdr*)(packet + sizeof(struct ether_header));
        // printIp(ip, *verbosite );
        // break;
        case ETHERTYPE_ARP:
        arp = (struct arphdr*)(packet + sizeof(struct ether_header)); 
            printArp(arp, *verbosite ); 
        break;
        default:
        printf("EtherType not handled\n");
    }

	// if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)
 //    {
 //        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
 //                ntohs(ethernet->ether_type),
 //                ntohs(ethernet->ether_type));
 //        struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
 //        printIp(ip, *verbosite );  
 //    }
 //    else
 //        printf("Not an IP packet\n");

};

void printDump(u_char *packet, int length){
    int i;
    for(i=0;i< length;i++){
        if(i%16==15)
            printf("%02x\n", (packet[i]));
        printf("%02x ", (packet[i]));
    }
    printf("\n");

};

void printAscii(u_char *packet, int length){
    int i;
    for(i=0;i< length;i++){
        if(isprint(packet[i])){        
        printf("%c", (packet[i]));
        }
        else
            printf(".");
        if(i%64==63)
            printf("\n");
    }
    printf("\n");

};

void printEthernet(struct ether_header* ethernet, int verbosite)
{
    if(verbosite>0){
        printf("**********En-tete Ethernet**********\n");
        printf("Destination host address : ");
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
         ((unsigned)ethernet->ether_dhost[0]),
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
        printf("Protocole : %u\n", (unsigned short) ethernet->ether_type);
        if(verbosite>0)
            printDump((u_char *) ethernet, sizeof(struct ether_header));
    }

};

void printIp(struct iphdr* ip, int verbosite)
{
    printf("**********En-tete IP**********\n");
    printf("Version : %d\n", ip->version);
    if(verbosite>0){ //2
        printf("Taille de l'en-tete : %d\n", ip->ihl);
        printf("Type de service : %d\n", ip->tos);
        printf("Taille totale : %d\n", ntohs(ip->tot_len));
    }
    if(verbosite>0){ //3
        printf("Identification : %d\n", ntohs(ip->id));
        printf("TTL : %d\n", ip->ttl);
        printf("Checksum : %d\n", ip->check);
    }
    printf("Protocole : %d\n", ip->protocol);
    printf("IP Source : %s\n", inet_ntoa(*(struct in_addr *) &ip->saddr));
    printf("IP Destination : %s\n", inet_ntoa(*(struct in_addr *) &ip->daddr));
    if(verbosite>0) 
        printDump((u_char *) ip, sizeof(struct ip));  
};
void printArp(struct arphdr* arp, int verbosite)
{
    printf("**********En-tete ARP**********\n");
    printf("Type hardware : %u (%s) \n", ntohs(arp->ar_hrd),(ntohs(arp->ar_hrd) == 1) ? "Ethernet" : "Inconnu");
    printf("Type protocole : %u (%s) \n", arp->ar_pro,(ntohs(arp->ar_pro) == ETHERTYPE_IP) ? "IPv4" : "Inconnu");
    printf("Operation : %u (%s) \n", ntohs(arp->ar_op), (ntohs(arp->ar_op) == ARPOP_REQUEST)? "REQUEST" : "REPLY");
    u_char * content = (u_char *) arp + sizeof(struct arphdr);
    if (ntohs(arp->ar_hrd) == 1 && ntohs(arp->ar_pro) == ETHERTYPE_IP){
        printf("Adresse MAC source: %02x:%02x:%02x:%02x:%02x:%02x\n", content[0], content[1], content[2], content[3], content[4], content[5]); 
        printf("Adresse IP source: %d.%d.%d.%d\n", content[6],content[7],content[8],content[9]); 
        printf("Adresse MAC destination: %02x:%02x:%02x:%02x:%02x:%02x\n", content[10], content[11], content[12], content[13], content[14], content[15]); 
        printf("Adresse IP destination: %d.%d.%d.%d\n", content[16],content[17],content[18],content[19]); 
    }
    if(verbosite>0) 
         printDump((u_char *) arp, sizeof(struct arphdr)+20);
    // printf("Type hardware : %u (%s) \n", ntohs(arp->htype),(ntohs(arp->htype) == 1) ? "Ethernet" : "Inconnu");
    // printf("Type protocole : %u (%s) \n", arp->ptype,(ntohs(arp->ptype) == ETHERTYPE_IP) ? "IPv4" : "Inconnu");
    // printf("Operation : %u (%s) \n", ntohs(arp->oper), (ntohs(arp->oper) == ARP_REQUEST)? "REQUEST" : "REPLY");
    // if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == ETHERTYPE_IP){
    //     printf("Adresse MAC source: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]); 

    // printf("Adresse IP source: %d.%d.%d.%d\n", arp->spa[0],arp->spa[1],arp->spa[2],arp->spa[3]); 

    // printf("Adresse MAC destination: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]); 

    // printf("Adresse IP destination: %d.%d.%d.%d\n", arp->tpa[0],arp->tpa[1],arp->tpa[2],arp->tpa[3]); 
    //}
 
  /* If is Ethernet and IPv4, print packet contents */ 
 //  if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
 //    printf("Sender MAC: "); 

 //    for(i=0; i<6;i++)
 //        printf("%02X:", arpheader->sha[i]); 

 //    printf("\nSender IP: "); 

 //    for(i=0; i<4;i++)
 //        printf("%d.", arpheader->spa[i]); 

 //    printf("\nTarget MAC: "); 

 //    for(i=0; i<6;i++)
 //        printf("%02X:", arpheader->tha[i]); 

 //    printf("\nTarget IP: "); 

 //    for(i=0; i<4; i++)
 //        printf("%d.", arpheader->tpa[i]); 
    
 //    printf("\n"); 
    //  u_char hlen;        /* Hardware Address Length */ 
    // u_char plen;        /* Protocol Address Length */ 
    // u_int16_t oper;     /* Operation Code          */ 
    // u_char sha[6];      /* Sender hardware address */ 
    // u_char spa[4];      /* Sender IP address       */ 
    // u_char tha[6];      /* Target hardware address */ 
    // u_char tpa[4]; 
    // if(verbosite>0){ //2
    //     printf("Taille de l'en-tete : %d\n", ip->ihl);
    //     printf("Type de service : %d\n", ip->tos);
    //     printf("Taille totale : %d\n", ntohs(ip->tot_len));
    // }
    // if(verbosite>0){ //3
    //     printf("Identification : %d\n", ntohs(ip->id));
    //     printf("TTL : %d\n", ip->ttl);
    //     printf("Checksum : %d\n", ip->check);
    // }
    // printf("Protocole : %d\n", ip->protocol);
    // printf("IP Source : %s\n", inet_ntoa(*(struct in_addr *) &ip->saddr));
    // printf("IP Destination : %s\n", inet_ntoa(*(struct in_addr *) &ip->daddr));
    // if(verbosite>0) 
    //     printDump((u_char *) ip, sizeof(struct ip));  
};

void printTcp(struct tcphdr* tcp, int verbosite){
    printf("**********En-tete TCP**********\n");
    printf("Port source : %u\n",ntohs(tcp->source));
    printf("Port destination : %u\n",ntohs(tcp->dest));
    if(verbosite>0){//2
        printf("Numero de sequence : %u\n",ntohl(tcp->seq));
        printf("Numero d'acquittement : %u\n",ntohl(tcp->ack_seq));
        printf("Taille de l'en-tete : %d\n", tcp->doff);
    }
    if(verbosite>0){//1
        printf("Flags : ");
        if(tcp->urg != 0 )
            printf("URGENT ");
        if(tcp->ack != 0 )
            printf("ACK ");
        if(tcp->psh != 0 )
            printf("PUSH ");
        if(tcp->rst != 0 )
            printf("RESET ");
        if(tcp->syn != 0 )
            printf("SYN ");
        if(tcp->fin != 0 )
            printf("FINISH ");
        printf("\n");
    }
    else{
        printf("Flags URGENT : %d\n",tcp->urg);
        printf("Flags ACK : %d\n",tcp->ack);
        printf("Flags PUSH : %d\n",tcp->psh);
        printf("Flags RESET : %d\n",tcp->rst);
        printf("Flags SYN : %d\n",tcp->syn);
        printf("Flags FINISH : %d\n",tcp->fin);
    }
    if(verbosite>0){//3
        printf("Taille de la fenetre : %d\n", tcp->window);
        printf("Checksum : %d\n", tcp->check);
        printf("Pointeur URGENT : %d\n", tcp->urg_ptr);
    }
    if(verbosite>0) 
        printDump((u_char *) tcp, tcp->doff*4); 
};
void printUdp(struct udphdr* udp, int verbosite){
    printf("**********En-tete UDP**********\n");
    printf("Port source : %u\n",ntohs(udp->source));
    printf("Port destination : %u\n",ntohs(udp->dest));
    printf("Taille de l'en-tete : %d\n", ntohs(udp->len));
    printf("Checksum : %d\n", ntohs(udp->check));
    printAscii((u_char *) udp + sizeof(struct udphdr) , ntohs(udp->len)- sizeof(struct udphdr));
    if(verbosite>0){ 
        printDump((u_char *) udp, ntohs(udp->len));
    }
    // if(verbosite>0){//2
    //     printf("Numero de sequence : %u\n",ntohl(tcp->seq));
    //     printf("Numero d'acquittement : %u\n",ntohl(tcp->ack_seq));
    //     printf("Taille de l'en-tete : %d\n", tcp->doff);
    // }
    // if(verbosite>0){//1
    //     printf("Flags : ");
    //     if(tcp->urg != 0 )
    //         printf("URGENT ");
    //     if(tcp->ack != 0 )
    //         printf("ACK ");
    //     if(tcp->psh != 0 )
    //         printf("PUSH ");
    //     if(tcp->rst != 0 )
    //         printf("RESET ");
    //     if(tcp->syn != 0 )
    //         printf("SYN ");
    //     if(tcp->fin != 0 )
    //         printf("FINISH ");
    //     printf("\n");
    // }
    // else{
    //     printf("Flags URGENT : %d\n",tcp->urg);
    //     printf("Flags ACK : %d\n",tcp->ack);
    //     printf("Flags PUSH : %d\n",tcp->psh);
    //     printf("Flags RESET : %d\n",tcp->rst);
    //     printf("Flags SYN : %d\n",tcp->syn);
    //     printf("Flags FINISH : %d\n",tcp->fin);
    // }
    // if(verbosite>0){//3
    //     printf("Taille de la fenetre : %d\n", tcp->window);
    //     printf("Checksum : %d\n", tcp->check);
    //     printf("Pointeur URGENT : %d\n", tcp->urg_ptr);
    // }
    // if(verbosite>0) 
    //     printDump((u_char *) tcp, tcp->doff*4); 
};
