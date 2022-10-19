// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 13.10.2022
// File containing functions for timers

#include "flow.h"

void close_sock(t_Args *args){
    close(args->sock);
}

void connect_to_sock(t_Args *args){
    if (connect(args->sock, (struct sockaddr *)&args->collector, sizeof(args->collector))  == -1)
        err(1, "connect() failed");
}

void create_client_sock(t_Args *args){
    if ((args->sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)
        err(1,"socket() failed\n");
}

void send_flow(t_Args *args, t_Flow *flow, t_time *oldest, t_time *current){
    static uint32_t flows_exported = 0;
    uint8_t packet[PACKET_SIZE];
    t_Pkt *pkt = (t_Pkt *)packet;

    flow->first_sys /= MILISECONDS;
    flow->last_sys /= MILISECONDS;
    uint64_t sysup = get_SysUpTime(oldest, current)/MILISECONDS;

    // HEADER
    pkt->version = htons(VERSION);
    pkt->count = htons(1);
    pkt->SysUpTime = htonl(sysup);
    pkt->unix_secs = htonl(current->tv_sec);
    pkt->unix_nsecs = htonl(current->tv_usec*MILISECONDS);
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
    pkt->First = htonl(flow->first_sys);
    pkt->Last = htonl(flow->last_sys);
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

    delete_flow(flow);
    flows_exported++;
}