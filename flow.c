// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// NewFlow project for ISA

#include "flow.h"

// GLOBAL VARIABLES

t_Args args;
t_List list;
t_Date oldest_time;
t_Date current_time;

// Packet handling

// TODO -> CASY PRI TESTOVANI NESEDI JSOU TAM MIRNE ROZDILY (Mozna je to zaokrouhlenim?)
// TODO -> TCP_FLAGS

void process_tcp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port){
    struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = tcp_header->source; // TODO -> odstraneno nthos protoze neni potreba ho delat?
    *dst_port = tcp_header->dest;

}

void process_udp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port){
    struct udphdr *udp_header = (struct udphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = udp_header->source;
    *dst_port = udp_header->dest;

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
        double first_diff = get_difference(&first, &sdate);
        double last_diff = get_difference(&last, &sdate);
        // printf("FD %lf LD %lf \n", first_diff, last_diff);
        if(first_diff > args.activeTimer || last_diff > args.inactiveTimer){
            printf("POSILAM \n"); // TODO
            send_flow(&args, current, &oldest_time, &current_time);
        }
        current = current->next;
    }
}

t_FlowHeader *create_header(struct timeval *secs){ //TODO
    t_FlowHeader *header = (t_FlowHeader*)malloc(sizeof(t_FlowHeader));  //TODO Osetrit malloc fail!
    header->version = VERSION;
    header->count = COUNT;
    header->unix_secs = secs->tv_sec; // TODO
    header->unix_nsecs = secs->tv_usec*MILISECONDS; // TODO
    header->flow_sequence = COUNT; // TODO
    header->engine_type = 0;
    header->engine_id = 0;
    header->sampling_interval = 0;

    return header;
}

void delete_header(t_FlowHeader *header){ //TODO
    free(header);
}

t_Flow *create_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type, char *time, uint32_t octets, struct timeval *secs, uint8_t tos){ //TODO
    t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow)); //TODO Osetrit malloc fail!
    flow->header = create_header(secs);
    flow->next = NULL;

    flow->src_IP = src_ip;
    flow->dst_IP = dst_ip;
    flow->next_hop = 0;
    flow->input = 0;
    flow->output = 0;
    flow->dPkts = 1;
    flow->dOctets = octets; // TODO
    strcpy(flow->first, time);
    strcpy(flow->last, time);
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->pad1 = 0;
    flow->tpc_flags = 0; // TODO
    flow->prot = type;
    flow->tos = tos; // TODO
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

void sniffer_callback(u_char *arguments, const struct pcap_pkthdr *packet_header, const u_char *data){
    // Ethernet header
    const struct ether_header *ethernet = (struct ether_header *)data;
    if(ntohs(ethernet->ether_type) != ETHERTYPE_IP){
        return;
    }

    // Getting arrival time and date (time representing "present")
    char miliseconds[MILISECONDS+1];
    char date_format[DATE_FORMAT] = "%F %T.";
    char time[TIME_LEN];
    struct timeval secs = packet_header->ts;

    snprintf(miliseconds, MILISECONDS, "%ld", secs.tv_usec);
    strcat(date_format, miliseconds);
	strftime(time, sizeof(time), date_format, localtime(&packet_header->ts.tv_sec));

    static int pkt_cnt = 0;
    if(pkt_cnt == 0){
        pkt_cnt++;
        oldest_time = split_date(time);
    }
    current_time = split_date(time);

    // Checking if timers were exceeded
    if(list.head){
        check_timers(time);
    }

    // TODO -> zjistit jestli resit nejak i ipv6 nebo ne
    uint8_t protocol_type;
    int ip_header_len;
    // char ip_src[IP_LEN];
    // char ip_dst[IP_LEN];
    uint32_t ip_src;
    uint32_t ip_dst;

    // Getting information from ip header
    // Using ip not iphdr for better unix compability (iphdr is only for Linux)
    struct ip* ipv4_header = (struct ip *)(data + sizeof(struct ether_header));
    protocol_type = ipv4_header->ip_p;
    ip_header_len = ipv4_header->ip_hl*4;
    ip_src = ipv4_header->ip_src.s_addr;
    ip_dst = ipv4_header->ip_dst.s_addr;
    uint8_t tos = ipv4_header->ip_tos;
    // Getting packet length
    uint32_t len = htons(ipv4_header->ip_len); // TODO -> pozjistovat jak vytahnout velikost ktera je pozadovana
    // printf("LEN = %d \n", len);

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    switch (protocol_type){ // Processing different protocol types
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
    if(!flow){ // No such flow in list
        if(list.counter >= args.count){ // Max of flows being in list was reached
            send_flow(&args, list.head, &oldest_time, &current_time); // Sending oldest_time flow
        }
        flow = create_flow(ip_src, ip_dst, src_port, dst_port, protocol_type, time, len, &secs, tos); // TODO
    }
    else{ // Flow exists so we update it 
        update_flow(flow, time, len); // TODO
    }
}

int main(int argc, char **argv){

    args = ctor_Args();
    list = ctor_List();
    parse_arguments(argc, argv, &args);
    printf("%s a %s a %d a %lf a %lf a %i\n", args.fileName, inet_ntoa(args.collector.sin_addr), ntohs(args.collector.sin_port), args.activeTimer, args.inactiveTimer, args.count);

    create_client_sock(&args);
    connect_to_sock(&args);

    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *sniffer = pcap_open_offline(args.fileName, error_buffer);
    if(!sniffer){
      fprintf(stderr, "Error! Could not open file! \n Error: \n\t%s \n", error_buffer);
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
        printf("FLOW: \n sip: %d dip: %d sp: %d dp: %d pr: %d pp: %d po: %d f: %s l: %s \n", current->src_IP, current->dst_IP, current->src_port, current->dst_port, current->prot, current->dPkts, current->dOctets, current->first, current->last);
        tmp = current->next;
        send_flow(&args, current, &oldest_time, &current_time);
        current = tmp;
    }

    pcap_freecode(&fp);
    pcap_close(sniffer);

    close_sock(&args);
    return 0;
}