// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// NewFlow project for ISA

#include "flow.h"

// GLOBAL VARIABLES

t_Args args;

// Packet handling

void process_tcp(const u_char *data, int ip_header_len, unsigned *src_port, unsigned *dst_port){
    struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = ntohs(tcp_header->source);
    *dst_port = ntohs(tcp_header->dest);

}

void process_udp(const u_char *data, int ip_header_len, unsigned *src_port, unsigned *dst_port){
    struct udphdr *udp_header = (struct udphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = ntohs(udp_header->source);
    *dst_port = ntohs(udp_header->dest);

}

void process_icmp(){
    // Could write any data specific for icmp
}

void check_timers(); // Tahle funkce na zaklade nove nastaveneho casu zkontroluje, ktere flows je potreba odeslat na kolektor

t_FlowHeader *create_header(){ //TODO
    t_FlowHeader *header = (t_FlowHeader*)malloc(sizeof(t_FlowHeader));

    return header;
}

void delete_header(t_FlowHeader *header){ //TODO
    free(header);
}

t_Flow *create_flow(char *src_ip){ //TODO
    t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow));
    strcpy(flow->src_IP, src_ip);

    return flow;
}

void delete_flow(t_Flow *flow){ //TODO
    free(flow);
}

void sniffer_callback(u_char *arguments, const struct pcap_pkthdr *packet_header, const u_char *data){
    // Jaky bude tady prubeh
    // Kontrola jestli mame IP header
    // Pokud ano tak ziskame cas z paketu a nastavime ho jako aktualni
    // Zkontrolujeme pomoci odectu jake flows je potreba odeslat na kolektor a odesleme je (jeden po druhem spolecne s jejich headry)
    // Podivame se jestli uz existuje flow do ktere bychom mohli paket pridat
    // Pokud ano, tak aktualizujeme data, ktere flow drzi
    // Pokud ne, tak vytvorime flow

    // Ethernet header
    const struct ether_header *ethernet = (struct ether_header *)data;

    if(ntohs(ethernet->ether_type) != ETHERTYPE_IP){
        return;
    }


    // Getting timestamp
    // TODO -> UDELAT ARRIVAL TIME A ODECTY MEZI LAST A FIRST PRO KONTROLU TIMERU!
    printf("PACKET: \n\n");
    char miliseconds[MILISECONDS+1];
    char date_format[DATE_FORMAT] = "%F %T.";
    char time_zone[TIME_ZONE] = "%z";
    
    snprintf(miliseconds, MILISECONDS, "%ld", packet_header->ts.tv_usec);
    printf("%s  \n", miliseconds);
    strcat(date_format, miliseconds);
    printf("%s  \n", date_format);
    // strcat(date_format, time_zone);
    // printf("%s  \n", date_format);

    char time[TIME_LEN];
	size_t zone = strftime(time, sizeof(time), date_format, localtime(&packet_header->ts.tv_sec));
    printf("%s  \n", time);
    
    // Getting packet length
    int len = packet_header->len;

    // Determining whether we have IPv4 or IPv6
    int protocol_type;
    int ip_header_len;
    char ip_src[IP_LEN];
    char ip_dst[IP_LEN];
    // char type_ip[TYPE_IP];

    // Using ip not iphdr for better unix compability (iphdr is only for Linux)
    struct ip* ipv4_header = (struct ip *)(data + sizeof(struct ether_header));
    protocol_type = ipv4_header->ip_p;
    ip_header_len = ipv4_header->ip_hl*4;
    // strcpy(type_ip, "IP");
    strcpy(ip_src, inet_ntoa((struct in_addr)ipv4_header->ip_src));
    strcpy(ip_dst, inet_ntoa((struct in_addr)ipv4_header->ip_dst));

   //  Determining which protocol we have and printing his info

   unsigned src_port = 0;
   unsigned dst_port = 0;
//    char protocol_str[20] = "";

    switch (protocol_type){
        case ICMP: // ICMP
            process_icmp();
            // strcpy(protocol_str, "ICMP");
            break;

        case TCP: // TCP
            process_tcp(data, ip_header_len, &src_port, &dst_port);
            // strcpy(protocol_str, "TCP");
            break;
    
        case UDP: // UDP
            process_udp(data, ip_header_len, &src_port, &dst_port);
            // strcpy(protocol_str, "UDP");
            break;
    
        default:
            break;
    }

    t_Flow *flow = create_flow(ip_src); // TODO 
    printf("FLOW VYPIS: %s \n\n", flow->src_IP);
    delete_flow(flow);
    // printf("src ip: %s a dst ip %s", ip_src, ip_dst);
    // printf(" src: %u a dst: %u a %s\n", src_port, dst_port);

}

int main(int argc, char **argv){

   args = ctor_Args();
   parse_arguments(argc, argv, &args);
   printf("%s a %s a %i a %i a %i\n", args.fileName, args.collector, args.activeTimer, args.seconds, args.count);

   char error_buffer[PCAP_ERRBUF_SIZE];

   pcap_t *sniffer = pcap_open_offline(args.fileName, error_buffer);
   if(!sniffer){
      fprintf(stderr, "Error! Could not open device! \n Error: \n\t%s \n", error_buffer);
      exit(-1);
   }

   char filter[FILTER_LEN] = FILTER;

   // Compiling and parsing filter
    struct bpf_program fp;
    if (pcap_compile(sniffer, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error! Could not compile filter! \nFilter: \n\t %s \nError: \n\t%s \n", filter, pcap_geterr(sniffer));
        exit(-1);
    }
    
    // Applying filter
    if (pcap_setfilter(sniffer, &fp) == -1) {
        fprintf(stderr, "Error! Could not set filter! \nFilter: \n\t %s \nError: \n\t%s \n", filter, pcap_geterr(sniffer));
        exit(-1);
    }

    // Waiting for packets in loop
    pcap_loop(sniffer, NUMBER_PACKETS, sniffer_callback, NULL);

   return 0;
}