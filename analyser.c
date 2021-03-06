#include "analyser.h"

#define BUFFER_SIZE 1024

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
            int sport = ntohs(tcp->source);
            int dport = ntohs(tcp->dest);
            u_char *data = (u_char *)tcp + 4*tcp->doff;
            int datasize = header->len - sizeof(tcp) - 4*tcp->doff;
            //if(tcp->psh!=0){
                if(sport == 80 || dport == 80){
                    if(*verbosite==1)
                        printf("Donnees HTTP\n");
                    else
                        printHttp(data, datasize, *verbosite);                  
                }    
                else if(sport == 21 || dport == 21){
                    printf("Donnees de controle FTP\n");
                    if(*verbosite>1)
                       printAscii(data, datasize);                  
                }
                else if(sport == 20 || dport == 20){
                    printf("Donnees de transfert FTP\n");
                    if(*verbosite>1)
                        printAscii(data, datasize);                  
                }
                else if(sport == 53 || dport == 53){
                printDns((u_char *)packet + datasize,*verbosite,1);
                } 
                else if( sport == 25 || dport == 25){
                    printf("Donnees SMTP\n");
                    if(*verbosite>1)
                        printAscii(data, datasize);
                } 
                else if(sport == 143 || dport == 143){
                    printf("Donnees IMAP\n");
                    if(*verbosite>1)
                        printAscii(data, datasize);                    
                } 
                else if(sport == 110 || dport == 110){
                    printf("Donnees POP3\n");
                    if(*verbosite>1)
                        printAscii(data, datasize);
                }
                else if(sport == 23 || dport == 23){
                    printf("Donnees TELNET\n");
                    if(*verbosite>1)
                        printTelnet(data, datasize, *verbosite);

                    //printDump(data, datasize);
                    //printf("----------------------------\n");
                    //printAscii(packet, header->len);
                }   
            //}         
            break;
            case IPPROTO_UDP:
            udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip->ihl*4); 
            printUdp(udp, *verbosite ); 
            if((ntohs(udp->source)==IPPORT_BOOTPS && ntohs(udp->dest)==IPPORT_BOOTPC) || 
                (ntohs(udp->dest)==IPPORT_BOOTPS && ntohs(udp->source)==IPPORT_BOOTPC)){
                printBootp((struct bootp*) (packet + sizeof(struct ether_header) + ip->ihl*4+8),*verbosite);
            }
            else if(ntohs(udp->source)== 53 || ntohs(udp->dest)==53){
                printDns((u_char *)packet + sizeof(struct ether_header) + ip->ihl*4+8,*verbosite,1);
            }
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
};

void printDump(u_char *packet, int length){
    int i;
    for(i=0;i< length;i++){
        if(i%16==15)
            printf("%02x\n", (packet[i]));
        else
            printf("%02x ", (packet[i]));
    }
    printf("\n");

};

void printAscii(u_char *packet, int length){
    int i;
    int rank =0;
    for(i=0;i< length;i++, rank++){
        if(isprint(packet[i])){        
            printf("%c", (packet[i]));
        }
        else if(packet[i] == '\n'){        
            printf("%c", (packet[i]));
            rank=0;
        }
        else if(packet[i] == '\r'){        
        printf("%c", (packet[i]));
            rank=0;
        }
        else
            printf(".");
        if(rank%64==63)
            printf("\n");
    }
    printf("\n");

};

void printEthernet(struct ether_header* ethernet, int verbosite)
{
    if(verbosite>1){
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
        if(verbosite>2)
            printDump((u_char *) ethernet, sizeof(struct ether_header));
    }

};

void printIp(struct iphdr* ip, int verbosite)
{
    printf("**********En-tete IP**********\n");
    if(verbosite>1){
        printf("Version : %d\n", ip->version);
        printf("Taille de l'en-tete : %d\n", ip->ihl);
        printf("Type de service : %d\n", ip->tos);
        printf("Taille totale : %d\n", ntohs(ip->tot_len));    
    if(verbosite>2){ //3
        printf("Identification : %d\n", ntohs(ip->id));
        printf("TTL : %d\n", ip->ttl);
        printf("Checksum : %d\n", ip->check);
    }
    printf("Protocole : %d\n", ip->protocol);
}
printf("IP Source : %s\n", inet_ntoa(*(struct in_addr *) &ip->saddr));
printf("IP Destination : %s\n", inet_ntoa(*(struct in_addr *) &ip->daddr));
if(verbosite>2) 
    printDump((u_char *) ip, sizeof(struct ip));  
};

void printArp(struct arphdr* arp, int verbosite){    
    printf("**********En-tete ARP**********\n");
    if(verbosite>1){
        printf("Type hardware : %u (%s) \n", ntohs(arp->ar_hrd),(ntohs(arp->ar_hrd) == 1) ? "Ethernet" : "Inconnu");
        printf("Type protocole : %u (%s) \n", arp->ar_pro,(ntohs(arp->ar_pro) == ETHERTYPE_IP) ? "IPv4" : "Inconnu");
    }
    printf("Operation : %u (%s) \n", ntohs(arp->ar_op), (ntohs(arp->ar_op) == ARPOP_REQUEST)? "REQUEST" : "REPLY");
    u_char * content = (u_char *) arp + sizeof(struct arphdr);
    if (ntohs(arp->ar_hrd) == 1 && ntohs(arp->ar_pro) == ETHERTYPE_IP){
        printf("Adresse MAC source: %02x:%02x:%02x:%02x:%02x:%02x\n", content[0], content[1], content[2], content[3], content[4], content[5]); 
        printf("Adresse IP source: %d.%d.%d.%d\n", content[6],content[7],content[8],content[9]); 
        printf("Adresse MAC destination: %02x:%02x:%02x:%02x:%02x:%02x\n", content[10], content[11], content[12], content[13], content[14], content[15]); 
        printf("Adresse IP destination: %d.%d.%d.%d\n", content[16],content[17],content[18],content[19]); 
    }    
    if(verbosite>2) 
        printDump((u_char *) arp, sizeof(struct arphdr)+20);
};

void printTcp(struct tcphdr* tcp, int verbosite){
    printf("**********En-tete TCP**********\n");
    printf("Port source : %u\n",ntohs(tcp->source));
    printf("Port destination : %u\n",ntohs(tcp->dest));
    if(verbosite>2){//2
        printf("Numero de sequence : %u\n",ntohl(tcp->seq));
        printf("Numero d'acquittement : %u\n",ntohl(tcp->ack_seq));
        printf("Taille de l'en-tete : %d\n", tcp->doff);
    }
    if(verbosite==1){//1
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
    if(verbosite>2){//3
        printf("Taille de la fenetre : %d\n", tcp->window);
        printf("Checksum : %d\n", tcp->check);
        printf("Pointeur URGENT : %d\n", tcp->urg_ptr);
    }
    if(verbosite>2) 
        printDump((u_char *) tcp, tcp->doff*4); 
};
void printUdp(struct udphdr* udp, int verbosite){
    printf("**********En-tete UDP**********\n");
    printf("Port source : %u\n",ntohs(udp->source));
    printf("Port destination : %u\n",ntohs(udp->dest));
    if(verbosite>1){
        printf("Taille de l'en-tete : %d\n", ntohs(udp->len));
        printf("Checksum : %d\n", ntohs(udp->check));
    }
    //printAscii((u_char *) udp + sizeof(struct udphdr) , ntohs(udp->len)- sizeof(struct udphdr));
    if(verbosite>3){ 
        printDump((u_char *) udp, ntohs(udp->len));
    }   
};
void printBootp(struct bootp* bp, int verbosite){
    printf("**********En-tete BOOTP**********\n");
    printf("Operation : %d ",bp->bp_op);
    if(bp->bp_op == BOOTREQUEST)
        printf("(REQUETE)\n");
    if(bp->bp_op == BOOTREPLY)
        printf("(REPONSE)\n");
    if(verbosite>3){
        printf("Type d'addresse hardware : %d\n",bp->bp_htype);
        printf("Taille d'addresse hardware : %d\n",bp->bp_hlen);
        printf("Nombre de sauts : %d\n",bp->bp_hops);
        printf("ID de transaction : %u\n",ntohl(bp->bp_xid));
        printf("Secondes depuis le boot : %d\n",ntohs(bp->bp_secs)); 
    }   
    printf("IP Client : %s\n", inet_ntoa(bp->bp_ciaddr));
    printf("Your IP : %s\n", inet_ntoa(bp->bp_yiaddr));
    printf("IP Server : %s\n", inet_ntoa(bp->bp_siaddr));
    printf("IP de la passerelle : %s\n", inet_ntoa(bp->bp_giaddr));
    int i;
    printf("Adresse MAC client : %02x",bp->bp_chaddr[0]);
    for(i=1;i<bp->bp_hlen;i++)
        printf(":%02x",bp->bp_chaddr[i]);
    printf("\n");
    printf("Nom du serveur : %s\n", bp->bp_sname);
    if(verbosite>3)
        printf("Fichier de boot : %s\n", bp->bp_file);
    if( bp->bp_vend[0] == 99 && bp->bp_vend[1] == 130 && bp->bp_vend[2] == 83 && bp->bp_vend[3] == 99 ){
        printf("Presence du MAGIC COOKIE\n");
        printf("Options : ");
        i = 4;
        while(bp->bp_vend[i]!=0xFF){
            switch(bp->bp_vend[i]){
                case TAG_DHCP_MESSAGE:
                switch(bp->bp_vend[i+2]){
                    case DHCPDISCOVER:
                    printf("DHCP DISCOVER\n");
                    break;
                    case DHCPOFFER:
                    printf("DHCP OFFER\n");
                    break;
                    case DHCPDECLINE:
                    printf("DHCP DECLINE\n");
                    break;
                    case DHCPACK:
                    printf("DHCP ACK\n");
                    break;
                    case DHCPNAK:
                    printf("DHCP NACK\n");
                    break;
                    case DHCPRELEASE:
                    printf("DHCP RELEASE\n");
                    break;
                    default:
                    break;
                }
                break;
                case TAG_CLIENT_ID:
                printf("Type materiel : %d (%s)\n",bp->bp_vend[i+2],(bp->bp_vend[i+2] == 1) ? "Ethernet" : "Inconnu");
                int j =i+3;
                printf("Adresse ethernet de l'equipement : %02x",bp->bp_vend[j]); 
                for(j++;j<bp->bp_vend[i+1]+i+2;j++)
                    printf(":%02x",bp->bp_vend[j]);
                printf("\n");            
                break;
                case TAG_HOSTNAME:
                printf("Nom de la machine : ");
                printAscii((u_char *) &bp->bp_vend[i+2],bp->bp_vend[i+1]-1);
                break;
                case TAG_PARM_REQUEST:
                printf("Parametres demandees :\n");
                j =i+3;
                for(;j<bp->bp_vend[i+1]+i+2;j++)
                    switch(bp->bp_vend[j]){
                        case TAG_GATEWAY:
                        printf("ROUTER ");
                        break;
                        case TAG_DOMAIN_SERVER:
                        printf("DNS ");
                        break;
                        case TAG_DOMAINNAME:
                        printf("DOMAIN_NAME ");
                        break;
                        case TAG_BROAD_ADDR:
                        printf("BROADCAST_ADDRESS ");
                        break;
                        case TAG_SUBNET_MASK:
                        printf("SUBNET_MASK ");
                        break;
                        case TAG_TIME_OFFSET:
                        printf("TIME_OFFSET ");
                        break;
                        case TAG_HOSTNAME:
                        printf("HOST_NAME ");
                        break;
                        case TAG_NETBIOS_NS:
                        printf("NETBIOS_OVER_TCP/IP_NAME_SERVER ");
                        break;
                        case TAG_NETBIOS_SCOPE:
                        printf("NETBIOS_OVER_TCP/IP_SCOPE ");
                        break;
                        case TAG_REQUESTED_IP:
                        printf("REQUESTED_IP_ADDRESS ");
                        break;
                        case TAG_IP_LEASE:
                        printf("LEASE_TIME ");
                        break;
                        case TAG_SERVER_ID:
                        printf("SERVER_ID ");
                        break;
                        case TAG_PARM_REQUEST:
                        printf("PARAMETER_REQUEST_LIST ");
                        break;
                        default:
                        printf("UNKNOWN ");
                        break;
                    }                
                    printf("\n"); 
                    break;
                    case TAG_GATEWAY:
                    j =i+3;
                    printf("Adresse IP du routeur : %d",bp->bp_vend[j]); 
                    for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                        printf(".%d",bp->bp_vend[j]);
                    printf("\n");
                    break;
                    case TAG_DOMAIN_SERVER:
                    j =i+3;
                    printf("Adresse IP du server DNS : %d",bp->bp_vend[j]); 
                    for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                        printf(".%d",bp->bp_vend[j]);
                    printf("\n");
                    break;
                    case TAG_DOMAINNAME:
                    printf("Nom de domaine : ");
                    printAscii((u_char *) &bp->bp_vend[i+2],bp->bp_vend[i+1]-1);
                    break;
                    case TAG_BROAD_ADDR:
                    j =i+3;
                    printf("Adresse IP de broadcast : %d",bp->bp_vend[j]); 
                    for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                        printf(".%d",bp->bp_vend[j]);
                    printf("\n");
                    break;
                    case TAG_SUBNET_MASK:
                    j =i+3;
                    printf("Masque de sous-reseau : %d",bp->bp_vend[j]); 
                    for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                        printf(".%d",bp->bp_vend[j]);
                    printf("\n");
                    break;
                    case TAG_TIME_OFFSET:
                printf("TIME_OFFSET \n");//TODO Non capturer
                printf("Decalage : %u s\n",bp->bp_vend[i+2]*256*256*256+bp->bp_vend[i+3]*256*256+bp->bp_vend[i+4]*256+bp->bp_vend[i+5]);
                break;
                case TAG_NETBIOS_NS:
                j =i+3;
                printf("Adresse IP serveur de nom: %d",bp->bp_vend[j]); 
                for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                    printf(".%d",bp->bp_vend[j]);
                printf("\n");
                break;
                case TAG_NETBIOS_SCOPE://TODO Non capturer
                j =i+3;
                printf("NETBIOS_OVER_TCP/IP_SCOPE : %d",bp->bp_vend[j]); 
                for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                    printf(".%d",bp->bp_vend[j]);
                printf("\n");
                break;
                case TAG_REQUESTED_IP:
                j =i+3;
                printf("Adresse IP demandee : %d",bp->bp_vend[j]); 
                for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                    printf(".%d",bp->bp_vend[j]);
                printf("\n");
                break;
                case TAG_IP_LEASE:
                printf("Temps de bail : %u s\n",bp->bp_vend[i+2]*256*256*256+bp->bp_vend[i+3]*256*256+bp->bp_vend[i+4]*256+bp->bp_vend[i+5]);
                break;
                case TAG_SERVER_ID:
                j =i+3;
                printf("Adresse IP server : %d",bp->bp_vend[j]); 
                for(j++;j<bp->bp_vend[i+1]+i+3;j++)
                    printf(".%d",bp->bp_vend[j]);
                printf("\n");
                break;
                default:
                printf("Option non prise en charge : %d\n",bp->bp_vend[i]);
                break;
            }
            i+=2+bp->bp_vend[i+1];
        }
    }
    if(verbosite>2)
        printDump((u_char *) bp, sizeof(struct bootp));

};

void printHttp(u_char *data, int datasize, int verbosite){//TODO encodage du message
    printf("**********HTTP**********\n");
    //char* donnees = strstr((const char *)data, "\r\n\r\n");
    if(strncmp((const char *)data, "HTTP/",5)==0){
        printf("REPONSE HTTP\n");
        int i=0;
        while(strncmp((const char *)data+i,"\r\n",2)!=0 && i<datasize)
            i++;
        printAscii(data,i);
        printf("HTTP Version : ");
        printAscii(data + 5, 3);
        printf("Code reponse : ");
        printAscii(data + 5 + 4 , 3);
        printf("Message : "); 
        printAscii(data + 5+8, i-13);
        int j = i+2;
        while(strncmp((const char *)data+j,"\r\n\r\n",4)!=0 && i<datasize)
            j++;
        printf("OPTIONS : ");
        printAscii(data + i + 2, j-i-2);
        printf("DONNEES : ");
        printAscii(data + i + 2 + j-i , datasize - j ) ;
        // printf("%d\n", sizeof(&donnees));
        // printAscii(data, datasize );
    }
    else if(strstr((const char *)data, "GET ")!=NULL || strstr((const char *)data, "HEAD ")!=NULL || strstr((const char *)data, "POST ")!=NULL){
        printf("REQUETE ");
        int i=0;
        while(strncmp((const char *)data+i,"\r\n",2)!=0 && i<datasize)
            i++;
        printAscii(data,i-8);
        printf("HTTP Version : ");
        printAscii(data + i-3, 3);
        int j = i+2;
        while(strncmp((const char *)data+j,"\r\n\r\n",4)!=0 && i<datasize)
            j++;
        printf("OPTIONS : ");
        printAscii(data + i + 2, j-i-2);
    }
    else{
        printf("Suite message\n");
        //printAscii(data, datasize );
    }    
    if(verbosite>2)
        printDump(data, datasize );
};

void printDns(u_char *data, int verbosite, int type){
    struct dns_header *dns;
    if(type==3){
        printf("**********DNS UDP**********\n");
        dns = (struct dns_header *)data+1;
    }
    else{
        printf("**********DNS TCP**********\n");
        dns = (struct dns_header *)data;
    }
    printf("%s DNS \n",(dns->flags >> 15 )?"REPONSE":"REQUETE");
    printf("Nombre de questions : %d\n",htons(dns->qd));
    printf("Nombre de reponses : %d\n",htons(dns->an));
    printf("Nombre de serveur de nom : %d\n",htons(dns->ns));
    printf("Nombre d'entrees additionnelles : %d\n",htons(dns->ar));

    u_char *dns_data = data + sizeof(struct dns_header);
    char buffer[256];
    bzero(buffer,256);
    int next_data = 0;
    int offset = 0;
    int i=0;
    int j=0;
    int nqd = htons(dns->qd);
    while(nqd>0){
        printf("Question : ");
        while(dns_data[i]!=0){
            for(j=i+1;j<=i+dns_data[i];j++)
                printf("%c",dns_data[j]);
            printf(".");
            i+=dns_data[i]+1;
        }
        printf("\n");
        // next_data=dns_data[offset];
        // memcpy(buffer,dns_data+offset+1,next_data);
        // buffer[next_data]='\0';
        // offset += (next_data+1);
        // printf("Question : %s\n",buffer);
        // printf("taille :%d\n", dns_data)
        //offset++;
        printf("Type : ");
        switch(dns_data[i+2]){
            case DNS_A:
            printf("A ");
            break;
            case DNS_NS:
            printf("NS ");
            break;
            case DNS_CNAME:
            printf("CNAME ");
            break;
            case DNS_SOA:
            printf("SOA ");
            break;
            case DNS_MX:
            printf("MX ");
            break;
            case DNS_AAAA:
            printf("AAAA ");
            break;
            default:
            printf(" %02x ",dns_data[i+2]);
            break;
        }
        printf("\nClasse : ");
        switch(dns_data[i+4]){
            case DNS_ANY:
            printf("ANY ");
            break;
            case DNS_IN:
            printf("IN ");
            break;
            default:
            printf("%02x ",dns_data[i+4]);
            break;
        }
        printf("\n"); 
        i+=5;
        nqd--;       
    }

    int nban = htons(dns->an);
    struct in_addr ip;
    //struct dns_answer *dns_a = ( struct dns_answer *)dns_data + i +1 ;
    //TODO DNS REPONSE 
    while(nban>0){
        printDump((u_char*) dns_data+i-1,140);
        printf("Reponse TTL : %d\n",dns_data[i+7]*255+dns_data[i+8]);        
        printf("Reponse : ");
        switch(dns_data[i+3]){
            case DNS_A:
            //ip.s_addr = htons(dns_data[i+8]);
            printf("%d.%d.%d.%d \n",dns_data[i+14],dns_data[i+13],dns_data[i+12],dns_data[i+11]);
            break;
            default:
            while(dns_data[j]!=0){
            for(j=10;j<dns_data[i+9];j++)
                printf("%c",dns_data[i+j]);
            printf(".");
        }
            break;
        }
        nban--;
        // while(dns_data[i]!=0){
        //     for(j=i+1;j<=i+dns_data[i];j++)
        //         printf("%c",dns_data[j]);
        //     printf(".");
        //     i+=dns_data[i]+1;
        // }
        // printf("\n");
        // next_data=dns_data[offset];
        // memcpy(buffer,dns_data+offset+1,next_data);
        // buffer[next_data]='\0';
        // offset += (next_data+1);
        // printf("Question : %s\n",buffer);
        // printf("taille :%d\n", dns_data)
        //offset++;
        // printf("Type : ");
        // switch(dns_data[i+2]){
        //     case DNS_A:
        //     printf("A ");
        //     break;
        //     case DNS_NS:
        //     printf("NS ");
        //     break;
        //     case DNS_CNAME:
        //     printf("CNAME ");
        //     break;
        //     case DNS_SOA:
        //     printf("SOA ");
        //     break;
        //     case DNS_MX:
        //     printf("MX ");
        //     break;
        //     case DNS_AAAA:
        //     printf("AAAA ");
        //     break;
        //     default:
        //     printf(" %02x ",dns_data[i+2]);
        //     break;
        // }
        // printf("\nClasse : ");
        // switch(dns_data[i+4]){
        //     case DNS_ANY:
        //     printf("ANY ");
        //     break;
        //     case DNS_IN:
        //     printf("IN ");
        //     break;
        //     default:
        //     printf("%02x ",dns_data[i+4]);
        //     break;
        // }
        // printf("\n"); 
        // i+=5;
        // nqd--;       
    }
    //TODO
};

// void printTelnet(u_char *packet, int length){
//     int i;
//     int rank =0;
//     int datasegment=1;
//     if(packet[0]==IAC){
//         datasegment=0;
//         printf("Negotiation d'options\n");
//     }

//     for(i=0;i< length;i++, rank++){
//         if(datasegment==0){
//             if(packet[i]==IAC){
//                 printf("IAC ");
//                 int not_default=0;
//                 switch(packet[i+1]){            
//             case SE:
//             printf("Fin_de_negotiation ");
//             break;
//             case NOP:
//             printf("No_Operation ");
//             break;
//             case DM:
//             printf("Data_Mark ");
//             break;
//             case IP:
//             printf("Interrupt_Process ");
//             break;
//             case AO:
//             printf("Abort_Output ");
//             break;
//             case AYT:
//             printf("Are_You_There ");
//             break;
//             case EC:
//             printf("Erase_Character ");
//             break;
//             case EL:
//             printf("Erase_Line ");
//             break;
//             case GA:
//             printf("Go_Ahead ");
//             break;
//             case SB:
//             printf("Subnegotiation ");
//             break;
//             case DONT:
//             printf("DONT ");
//             break;
//             case DO:
//             printf("DO ");
//             break;
//             case WONT:
//             printf("WONT ");
//             break;
//             case WILL:
//             printf("WILL ");
//             break;
//             default:
//             //printf("%02x ",packet[i]);
//             rank++;
//             i++;
//             not_default=1;
//             break;
//         }
//         if(not_default==0){
//             switch(packet[i+2]){
//                 case TELOPT_ECHO:
//             printf("Echo ");
//             break;
//             case TELOPT_BINARY:
//             if(packet[i+3]!=TELOPT_BINARY)
//                 printf("Binary_transmission ");
//             else
//                 datasegment=1;
//             break;
//             case SB:
//             printf("Subnegotiation ");
//             break;
//             case SE:
//             printf("Fin_de_negotiation ");
//             break;
//             case TELOPT_SGA:
//             printf("Suppress_go_ahead ");
//             break;
//             case TELOPT_SUPDUPOUTPUT:
//             printf("Line_mode ");
//             case TELOPT_TTYPE:
//             printf("Terminal_Type ");
//             break;
//             case TELOPT_NAWS:
//             printf("Window_size ");
//             if(packet[i+1]==SB){
//                 printf("%d %d ", packet[i+3]*256+packet[i+4], packet[i+5]*256+packet[i+6]);
//                 i=i+6;
//                 rank=rank+6;
//             }
//             break;
//             case TELOPT_TSPEED:
//             printf("Terminal_Speed ");
//             break;
//             case TELOPT_OLD_ENVIRON:
//             printf("Environment_variables ");
//             break;
//             case TELOPT_NEW_ENVIRON:
//             printf("New_Environnement_variable ");
//             break;
//             case IAC:
//             not_default=1;
//             rank=rank+2;
//             i=i+2;
//             break;
//             default:
//             printf("%02x ",packet[i+2]);
//             not_default=1;
//             rank=rank+2;
//             i=i+2;
//             break;
//             }
//         }
//             }
        
//     }
//         else{
//         if(isprint(packet[i])){        
//             printf("%c", (packet[i]));
//         }
//         else if(packet[i] == '\n'){        
//             printf("%c", (packet[i]));
//             rank=0;
//         }
//         else if(packet[i] == '\r'){        
//         printf("%c", (packet[i]));
//             rank=0;
//         }
//     }
        
//         if(rank%64>=63)
//             printf("\n");
//     }
//     printf("\n");

// };
void printTelnet(u_char *packet, int length, int verbosite){
    int i;
    int rank =0;
    int datasegment=1;
    if(packet[0]==IAC){
        datasegment=0;
        printf("Negotiation d'options\n");
    }
    else
        printf("Donnees\n");
    if(verbosite>2){
    for(i=0;i< length;i++, rank++){
        if(datasegment==0){
        switch(packet[i]){
            case IAC:
            printf("IAC ");
            break;
            case SE:
            printf("Fin_de_negotiation ");
            break;
            case NOP:
            printf("No_Operation ");
            break;
            case DM:
            printf("Data_Mark ");
            break;
            case IP:
            printf("Interrupt_Process ");
            break;
            case AO:
            printf("Abort_Output ");
            break;
            case AYT:
            printf("Are_You_There ");
            break;
            case EC:
            printf("Erase_Character ");
            break;
            case EL:
            printf("Erase_Line ");
            break;
            case GA:
            printf("Go_Ahead ");
            break;
            case SB:
            printf("Subnegotiation ");
            break;
            case DONT:
            printf("DONT ");
            break;
            case DO:
            printf("DO ");
            break;
            case WONT:
            printf("WONT ");
            break;
            case WILL:
            printf("WILL ");
            break;
            case TELOPT_ECHO:
            printf("Echo ");
            break;
            case TELOPT_BINARY:
            if(packet[i+1]!=TELOPT_BINARY)
                printf("Binary_transmission ");
            else
                datasegment=1;
            break;
            case TELOPT_SGA:
            printf("Suppress_go_ahead ");
            break;
            case TELOPT_SUPDUPOUTPUT:
            printf("Line_mode ");
            case TELOPT_TTYPE:
            printf("Terminal_Type ");
            break;
            case TELOPT_NAWS:
            printf("Window_size ");
            if(packet[i-1]==SB){
                printf("%d %d ", packet[i+1]*256+packet[i+2], packet[i+3]*256+packet[i+4]);
                i=i+4;
                rank=rank+4;
            }

            break;
            case TELOPT_TSPEED:
            printf("Terminal_Speed ");
            break;
            case TELOPT_OLD_ENVIRON:
            printf("Environment_variables ");
            break;
            case TELOPT_NEW_ENVIRON:
            printf("New_Environnement_variable ");
            break;
            default://l'option n'est pas reconnue
            printf("%02x ",packet[i]);
            break;
        }
    }
        else{
        if(isprint(packet[i])){        
            printf("%c", (packet[i]));
        }
        else if(packet[i] == '\n'){        
            printf("%c", (packet[i]));
            rank=0;
        }
        else if(packet[i] == '\r'){        
        printf("%c", (packet[i]));
            rank=0;
        }
    }
        
        if(rank%64>=63)
            printf("\n");
    }
    printf("\n");
}
};