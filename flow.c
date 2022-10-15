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

void check_timers(char *date){
    // ziskat den a cas z data
    t_Flow *current = list.head;
    t_Date sdate = split_date(date);

    while(current){
        t_Date first = split_date(current->first);
        t_Date last = split_date(current->last);
        double first_diff = get_difference(first, sdate);
        double last_diff = get_difference(last, sdate);
        // printf("FD %lf LD %lf \n", first_diff, last_diff);
        if(first_diff > args.activeTimer || last_diff > args.inactiveTimer){
            printf("POSILAM \n"); // TODO
            send_flow();
        }
        current = current->next;
    }
}

t_FlowHeader *create_header(){ //TODO
    t_FlowHeader *header = (t_FlowHeader*)malloc(sizeof(t_FlowHeader));  //TODO Osetrit malloc fail!
    header->version = VERSION;
    header->count = COUNT;
    strcpy(header->SysUptime, "time"); // TODO
    header->unix_secs = 0; // TODO
    header->unix_nsecs = 0; // TODO
    header->flow_sequence = COUNT; // TODO
    header->engine_type = 0;
    header->engine_id = 0;
    header->sampling_interval = 0;

    return header;
}

void delete_header(t_FlowHeader *header){ //TODO
    free(header);
}

t_Flow *create_flow(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type, char *time, uint32_t octets){ //TODO
   t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow)); //TODO Osetrit malloc fail!
   flow->header = create_header();
   flow->next = NULL;

   strcpy(flow->src_IP, src_ip);
   strcpy(flow->dst_IP, dst_ip);
   strcpy(flow->next_hop, "0.0.0.0");
   flow->input = 0;
   flow->output = 0;
   flow->dPkts = 1;
   flow->dOctets = octets; // TODO
   strcpy(flow->first, time);
   strcpy(flow->last, time);
   flow->src_port = src_port;
   flow->dst_port = dst_port;
   flow->pad1 = 0;
   flow->tpc_flags = 1; // TODO
   flow->prot = type;
   flow->tos = 1; // TODO
   flow->src_as = 0;
   flow->dst_as = 0;
   flow->src_mask = 0;
   flow->dst_mask = 0;
   flow->pad2 = 0;

   list_add(&list, flow);
   return flow;
}

void delete_flow(t_Flow *flow){ //TODO
   list_delete(&list, flow);
   delete_header(flow->header);

   free(flow);
}

void update_flow(t_Flow *flow, char *new_last, uint32_t add_octets){ //TODO
    flow->dPkts += 1;
    flow->dOctets += add_octets;
    strcpy(flow->last, new_last);
}

void send_flow(){
    printf("Sending \n");
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
    char miliseconds[MILISECONDS+1];
    char date_format[DATE_FORMAT] = "%F %T.";
    char time[TIME_LEN];

    snprintf(miliseconds, MILISECONDS, "%ld", packet_header->ts.tv_usec);
    strcat(date_format, miliseconds);
	size_t zone = strftime(time, sizeof(time), date_format, localtime(&packet_header->ts.tv_sec));

    // printf("%s  \n", time);

    if(list.head){
        check_timers(time);
    }

    // Getting packet length
    uint32_t len = packet_header->len; // TODO
    // printf("LEN = %d \n", len);

    // TODO -> zjistit jestli resit nejak i ipv6 nebo ne
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
        if(list.counter >= args.count){
            // TODO -> tady budeme muset najit nejstarsi flow
            send_flow();
        }
        flow = create_flow(ip_src, ip_dst, src_port, dst_port, protocol_type, time, len); // TODO
    }
    else{
        update_flow(flow, time, len); // TODO
    }
}

int main(int argc, char **argv){

   args = ctor_Args();
   list = ctor_List();
   parse_arguments(argc, argv, &args);
   printf("%s a %s a %lf a %lf a %i\n", args.fileName, args.collector, args.activeTimer, args.inactiveTimer, args.count);

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

    t_Flow *current = list.head; // TODO -> smazat
    t_Flow *tmp;
    while (current)
    {
        printf("FLOW: \n sip: %s dip: %s sp: %d dp: %d pr: %d pp: %d po: %d f: %s l: %s \n", current->src_IP, current->dst_IP, current->src_port, current->dst_port, current->prot, current->dPkts, current->dOctets, current->first, current->last);
        tmp = current->next;
        delete_flow(current);
        current = tmp;
    }


   return 0;
}