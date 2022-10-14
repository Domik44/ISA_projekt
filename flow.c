// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// NewFlow project for ISA

#include "flow.h"

// GLOBAL VARIABLES

t_Args args;
t_List list;


// Packet handling

void process_tcp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port){
    struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = ntohs(tcp_header->source);
    *dst_port = ntohs(tcp_header->dest);

}

void process_udp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port){
    struct udphdr *udp_header = (struct udphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = ntohs(udp_header->source);
    *dst_port = ntohs(udp_header->dest);

}

void process_icmp(){
    // Could write any data specific for icmp
}

void check_timers(); // Tahle funkce na zaklade nove nastaveneho casu zkontroluje, ktere flows je potreba odeslat na kolektor

t_FlowHeader *create_header(){ //TODO
    t_FlowHeader *header = (t_FlowHeader*)malloc(sizeof(t_FlowHeader));  //TODO Osetrit malloc fail!
    header->version = VERSION;
    header->engine_id = 0;
    header->engine_type = 0;
    header->sampling_interval = 0;
    header->count = COUNT;

    return header;
}

void delete_header(t_FlowHeader *header){ //TODO
    free(header);
}

t_Flow *create_flow(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type){ //TODO
   t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow)); //TODO Osetrit malloc fail!
   flow->header = create_header();
   flow->next = NULL;
   strcpy(flow->src_IP, src_ip);
   strcpy(flow->dst_IP, dst_ip);
   flow->src_port = src_port;
   flow->dst_port = dst_port;
   flow->prot = type;
   flow->dPkts = 1;

   list_add(&list, flow);
   return flow;
}

void delete_flow(t_Flow *flow){ //TODO
   list_delete(&list, flow);
   delete_header(flow->header);

   free(flow);
}

void update_flow(t_Flow *flow){ //TODO
    flow->dPkts += 1;
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
    // printf("PACKET: \n\n");
    char miliseconds[MILISECONDS+1];
    char date_format[DATE_FORMAT] = "%F %T.";
    char time_zone[TIME_ZONE] = "%z";
    
    snprintf(miliseconds, MILISECONDS, "%ld", packet_header->ts.tv_usec);
    // printf("%s  \n", miliseconds);
    strcat(date_format, miliseconds);
    // printf("%s  \n", date_format);
    // strcat(date_format, time_zone);
    // printf("%s  \n", date_format);

    char time[TIME_LEN];
	size_t zone = strftime(time, sizeof(time), date_format, localtime(&packet_header->ts.tv_sec));
    // printf("%s  \n", time);
    
    // Getting packet length
    int len = packet_header->len;

    // Determining whether we have IPv4 or IPv6
    uint8_t protocol_type;
    int ip_header_len;
    char ip_src[IP_LEN];
    char ip_dst[IP_LEN];

    // Using ip not iphdr for better unix compability (iphdr is only for Linux)
    struct ip* ipv4_header = (struct ip *)(data + sizeof(struct ether_header));
    protocol_type = ipv4_header->ip_p;
    ip_header_len = ipv4_header->ip_hl*4;
    strcpy(ip_src, inet_ntoa((struct in_addr)ipv4_header->ip_src));
    strcpy(ip_dst, inet_ntoa((struct in_addr)ipv4_header->ip_dst));

   //  Determining which protocol we have and printing his info

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    switch (protocol_type){
        case ICMP: // ICMP
            process_icmp();
            break;
        case TCP: // TCP
            process_tcp(data, ip_header_len, &src_port, &dst_port);
            break;
        case UDP: // UDP
            process_udp(data, ip_header_len, &src_port, &dst_port);
            break;
        default:
            break;
    }

    t_Flow *flow = list_find(&list, ip_src, ip_dst, src_port, dst_port, protocol_type);
    if(!flow){
        flow = create_flow(ip_src, ip_dst, src_port, dst_port, protocol_type);
    }
    else{
        update_flow(flow);
    }
}

int main(int argc, char **argv){

   args = ctor_Args();
   list = ctor_List();
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

    // t_Flow *current = list.head;
    // t_Flow *tmp;
    // while (current)
    // {
    //     printf("FLOW: \n %s a %d a %d \n", current->src_IP, current->src_port, current->dPkts);
    //     tmp = current->next;
    //     delete_flow(current);
    //     current = tmp;
    // }
    

   return 0;
}