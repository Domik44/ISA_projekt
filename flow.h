// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// Header file for flow.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <time.h>

#include<err.h>

#define ARG_LEN 40
#define DEFAULT_COUNT 1024
#define DEFAULT_INACTIVE 10
#define DEFAULT_TIMER 60
#define DEFAULT_COLLECTOR_IP "127.0.0.1"
#define DEFAULT_COLLECTOR_PORT 2055
#define FILTER "udp or tcp or icmp"
#define FILTER_LEN 30
#define NUMBER_PACKETS 0
#define IP_LEN 40
#define PORT_LEN 6

#define ICMP 1
#define TCP 6
#define UDP 17

#define VERSION 5
#define COUNT 1

#define DATE_FORMAT 20
#define MILISECONDS_LEN 3 // TODO Zmeneno aby to ukrajovalo a nezaokrouhluje to !!
#define MILISECONDS 1000
#define TIME_ZONE 3
#define TIME_LEN 50

#define HEADER_SIZE 24
#define FLOW_SIZE 48
#define PACKET_SIZE HEADER_SIZE + FLOW_SIZE // -> 72 (We are sending one flow per packet)

/**
 * @brief Structure for storing user input arguments
 * 
 */
typedef struct Args{
    char fileName[ARG_LEN];
    struct sockaddr_in collector;
    double activeTimer;
    double inactiveTimer;
    int count;
    struct hostent *servent;
    int sock;
}t_Args;

/**
 * @brief Structure for storing information about headers
 * 
 */
typedef struct FlowHeader{
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime; // TODO
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type; //TODO
    uint8_t engine_id; // TODO
    uint16_t sampling_interval; // TODO
}t_FlowHeader;


/**
 * @brief Structure for storing information about flow
 * 
 */
typedef struct Flow{
    uint32_t src_IP;
    uint32_t dst_IP;
    uint32_t next_hop;
    uint16_t input; //TODO
    uint16_t output; //TODO
    uint32_t dPkts;
    uint32_t dOctets;
    char first[TIME_LEN];
    char last[TIME_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t pad1; //TODO
    uint8_t tpc_flags; // TODO
    uint8_t prot;
    uint8_t tos; // TODO
    uint16_t src_as; //TODO
    uint16_t dst_as; //TODO
    uint8_t src_mask; //TODO
    uint8_t dst_mask; //TODO
    uint16_t pad2; // TODO
    struct Flow *next;
    struct Flow *previous;
    struct FlowHeader *header;
}t_Flow;

/**
 * @brief List structure for holding flows
 * 
 */
typedef struct List{
    t_Flow *head;
    t_Flow *last;
    int counter;
}t_List;

/**
 * @brief Structure for storing date
 * 
 */
typedef struct Date{
    char day[DATE_FORMAT];
    char month[DATE_FORMAT];
    char year[DATE_FORMAT];
    char hours[DATE_FORMAT];
    char minutes[DATE_FORMAT];
    char seconds[DATE_FORMAT];
}t_Date;


/**
 * @brief Constructor for argument structure
 * 
 * @return t_Args Rerturns allocated argument
 */
t_Args ctor_Args();

/**
 * @brief Function prints help instruction on stdout
 * 
 */
void help_function();

/**
 * @brief Function for parsing and storing arguments
 * 
 * @param argc Number of input arguments
 * @param argv String array of input arguments
 */
void parse_arguments(int argc, char **argv, t_Args *args);


/**
 * @brief Callback function used for handling recieved packets
 * 
 * @param arguments User arguments -> NULL for our project
 * @param packet_header Packet header storing packet information
 * @param data String containing packet data
 */
void sniffer_callback(u_char *arguments, const struct pcap_pkthdr *packet_header, const u_char *data);


/**
 * @brief Fucntion gets important information about TCP packet
 * 
 * @param data String containing packet data
 * @param ip_header_len Length of ip header
 */
void process_tcp(const u_char *data ,int ip_header_len, uint16_t *src_port, uint16_t *dst_port);

/**
 * @brief Fucntion gets important information about UDP packet
 * 
 * @param data String containing packet data
 * @param ip_header_len Length of ip header
 */
void process_udp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port);

/**
 * @brief 
 * 
 */
void process_icmp();

// Tohle bude funkce na kontrolovani timeru flow (ktere odeslat)
void check_times();

t_FlowHeader *create_header(struct timeval *secs);

void delete_header(t_FlowHeader *header);

t_Flow *create_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type, char *time, uint32_t octets, struct timeval *secs, uint8_t tos);

void delete_flow(t_Flow *flow);

t_List ctor_List();

void list_add(t_List *list, t_Flow *flow);

void list_delete(t_List *list, t_Flow *flow);

t_Flow *list_find(t_List *list, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type);

t_Date split_date(char *given);

double get_seconds(char *str);

double get_difference(t_Date *first, t_Date *last);

void send_flow(t_Args *args, t_Flow *flow, t_Date *oldest, t_Date *current);

void create_client_sock(t_Args *args);

void connect_to_sock(t_Args *args);

void close_sock(t_Args *args);