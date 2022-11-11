// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// NewFlow project for ISA

#include "flow.h"

// GLOBAL VARIABLES

t_Args *args;
t_List list;
t_time boot_time;
t_time current_time;

// Packet handling

// TODO -> CASY PRI TESTOVANI NESEDI JSOU TAM MIRNE ROZDILY (Mozna je to zaokrouhlenim?)
// TODO -> TCP_FLAGS

void process_tcp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port, uint8_t *tcp_flags){
    struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = tcp_header->source; // TODO -> odstraneno nthos protoze neni potreba ho delat?
    *dst_port = tcp_header->dest;
    *tcp_flags = tcp_header->th_flags; // TODO -> tady byl ten OR, ale byl umisten blbe

}

void process_udp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port){
    struct udphdr *udp_header = (struct udphdr *)(data + ip_header_len + sizeof(struct ether_header));
    *src_port = udp_header->source;
    *dst_port = udp_header->dest;

}

void check_timers(){
    t_Flow *current = list.head; 

    uint64_t sysuptime = get_SysUpTime(&boot_time, &current_time);

    while(current){
        uint64_t first_diff = sysuptime - current->first_sys;
        uint64_t last_diff = sysuptime - current->last_sys;
        if(sysuptime < current->first_sys || sysuptime < current->last_sys){
            current = current->next;
            continue;
        }

        if(first_diff > args->activeTimer || last_diff > args->inactiveTimer){
            // uint64_t s = get_SysUpTime(&boot_time, &current_time);
            // printf("TIMER: %lu %lu %lu \n", sysuptime, current->first_sys, current->last_sys);
            send_flow(args, current, &boot_time, &current_time);
        }
        current = current->next;
    }
}

t_Flow *create_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
     uint8_t type, uint32_t octets, uint8_t tos, uint8_t tcp_flags){ //TODO
    t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow)); //TODO Osetrit malloc fail!
    flow->next = NULL;

    flow->src_IP = src_ip;
    flow->dst_IP = dst_ip;
    flow->dPkts = 1;
    flow->dOctets = octets;
    flow->first_sys = get_SysUpTime(&boot_time, &current_time);
    flow->last_sys = get_SysUpTime(&boot_time, &current_time);
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->tpc_flags = tcp_flags;
    flow->prot = type;
    flow->tos = tos;

    list_add(&list, flow);
    return flow;
}

void delete_flow(t_Flow *flow){ //TODO
   list_delete(&list, flow);

   free(flow);
}

void update_flow(t_Flow *flow, uint32_t add_octets, uint8_t tcp_flags){ //TODO
    flow->dPkts += 1;
    flow->dOctets += add_octets;
    flow->last_sys = get_SysUpTime(&boot_time, &current_time);
    flow->tpc_flags |= tcp_flags;   
}

void sniffer_callback(u_char *arguments, const struct pcap_pkthdr *packet_header, const u_char *data){
    // Ethernet header
    const struct ether_header *ethernet = (struct ether_header *)data;
    if(ntohs(ethernet->ether_type) != ETHERTYPE_IP){
        return;
    }

    // Getting actual time
    current_time = packet_header->ts;
    static int pkt_cnt = 0;
    if(pkt_cnt == 0){
        // Setting boot time
        pkt_cnt++;
        boot_time = current_time;
    }

    // Checking if timers were exceeded
    if(list.head){
        check_timers();
    }

    // TODO -> zjistit jestli resit nejak i ipv6 nebo ne
    uint8_t protocol_type;
    int ip_header_len;
    uint32_t ip_src;
    uint32_t ip_dst;

    // Getting information from ip header
    // Using ip not iphdr for better unix compability (iphdr is only for Linux)
    struct ip* ipv4_header = (struct ip *)(data + sizeof(struct ether_header));
    // Getting protocol number
    protocol_type = ipv4_header->ip_p;
    ip_header_len = ipv4_header->ip_hl*4;
    // Getting ips
    ip_src = ipv4_header->ip_src.s_addr;
    ip_dst = ipv4_header->ip_dst.s_addr;
    // Getting tos
    uint8_t tos = ipv4_header->ip_tos;
    // Getting packet length
    uint32_t len = htons(ipv4_header->ip_len);

    // Getting ports
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;
    switch (protocol_type){ // Processing different protocol types
        case ICMP:
            break;
        case TCP:
            process_tcp(data, ip_header_len, &src_port, &dst_port, &tcp_flags);
            break;
        case UDP:
            process_udp(data, ip_header_len, &src_port, &dst_port);
            break;
        default:
            break;
    }

    t_Flow *flow = list_find(&list, ip_src, ip_dst, src_port, dst_port, protocol_type);
    if(!flow){ // No such flow in list
        if(list.counter >= args->count){ // Max of flows being in list was reached
            printf("Posilal bych \n"); // TODO -> odstranit
            send_flow(args, list.head, &boot_time, &current_time); // Sending oldest_time flow
        }
        flow = create_flow(ip_src, ip_dst, src_port, dst_port, protocol_type, len, tos, tcp_flags);
    }
    else{ // Flow exists so we update it 
        update_flow(flow, len, tcp_flags);
        if(tcp_flags & FIN || tcp_flags & RST){
            send_flow(args, list.head, &boot_time, &current_time); // Sending flow on FIN or RST
        }
    }
}

int main(int argc, char **argv){

    args = ctor_Args();
    list = ctor_List();
    parse_arguments(argc, argv, args);

    create_client_sock(args); // TODO nejake osetreni chyb
    connect_to_sock(args);

    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *sniffer = pcap_open_offline(args->fileName, error_buffer);
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

    // Sending rest of the flows
    t_Flow *current = list.head;
    t_Flow *tmp;
    while (current)
    {
        tmp = current->next;
        // uint64_t sysuptime = get_SysUpTime(&boot_time, &current_time);
        // printf("KONEC: %lu %lu %lu \n", sysuptime, current->first_sys, current->last_sys);
        send_flow(args, current, &boot_time, &current_time);
        current = tmp;
    }

    pcap_freecode(&fp);
    pcap_close(sniffer);

    close_sock(args);
    free(args);
    return 0;
}