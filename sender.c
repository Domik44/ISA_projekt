// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 13.10.2022
// File containing functions for timers

#include "flow.h"

typedef struct Pkt{
    // Header
    uint16_t version, count;
    uint32_t SysUpTime, unix_secs, unix_nsecs, flow_seq;
    uint8_t engine_type, engine_id;
    uint16_t sampling_int;
    // Flow
    uint32_t src_ip, dst_ip, next_hop;
    uint16_t input, output;
    uint32_t dPkts, dOcts, First, Last;
    uint16_t src_port, dst_port;
    uint8_t pad1, tcp_flags, prot, tos;
    uint16_t src_as, dst_as;
    uint8_t src_mask, dst_mask;
    uint16_t pad2;
}t_Pkt;

void close_sock(t_Args *args){
    close(args->sock);
}

void connect_to_sock(t_Args *args){
    if (connect(args->sock, (struct sockaddr *)&args->collector, sizeof(args->collector))  == -1)
        err(1, "connect() failed");
}

void create_client_sock(t_Args *args){
    if ((args->sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        err(1,"socket() failed\n");
}

void send_flow(t_Args *args, t_Flow *flow, t_Date *oldest, t_Date *current){
    static uint32_t flows_exported = 0;
    uint8_t packet[PACKET_SIZE];
    t_Pkt *pkt = (t_Pkt *)packet;
    t_Date first = split_date(flow->first);
    t_Date last = split_date(flow->last);

    // HEADER
    pkt->version = htons(VERSION);
    pkt->count = htons(1);
    pkt->SysUpTime = htonl(MILISECONDS*get_difference(oldest, current));
    pkt->unix_secs = htonl(flow->header->unix_secs);
    pkt->unix_nsecs = htonl(flow->header->unix_nsecs);
    pkt->flow_seq = htonl(flows_exported);
    pkt->engine_type = 0;
    pkt->engine_id = 0;
    pkt->sampling_int = 0;
    // FLOW
    pkt->src_ip = flow->src_IP;
    pkt->dst_ip = flow->dst_IP;
    pkt->next_hop = 0;
    pkt->input = 0;
    pkt->output = 0;
    pkt->dPkts = htonl(flow->dPkts);
    pkt->dOcts = htonl(flow->dOctets);
    pkt->First = htonl(MILISECONDS*get_difference(oldest, &first));
    pkt->Last = htonl(MILISECONDS*get_difference(oldest, &last));
    pkt->src_port = flow->src_port;
    pkt->dst_port = flow->dst_port;
    pkt->pad1 = 0;
    pkt->tcp_flags = flow->tpc_flags; // TODO 
    pkt->prot = flow->prot;
    pkt->tos = flow->tos;
    pkt->src_as = 0;
    pkt->dst_as = 0;
    pkt->src_mask = 0;
    pkt->dst_mask = 0;
    pkt->pad2 = 0;

    int i = send(args->sock,packet,PACKET_SIZE,0); // TODO -> posledni polozka flags

    printf("TU: %lf a TADY: %lf \n", MILISECONDS*get_difference(oldest, &first), MILISECONDS*get_difference(oldest, &last));

    delete_flow(flow);
    flows_exported++;
}