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

#define ARG_LEN 40
#define DEFAULT_COUNT 1024
#define DEFAULT_SECONDS 10
#define DEFAULT_TIMER 60
#define DEFAULT_COLLECTOR "127.0.0.1:2055"
#define FILTER "udp or tcp or icmp"
#define FILTER_LEN 30
#define NUMBER_PACKETS 0
#define IP_LEN 40
#define TYPE_IP 10
#define ICMP 1
#define TCP 6
#define UDP 17



#define DATE_FORMAT 20
#define MILISECONDS 6
#define TIME_ZONE 3
#define TIME_LEN 50

/**
 * @brief Structure for storing user input arguments
 * 
 */
typedef struct Args{
    char fileName[ARG_LEN];
    char collector[ARG_LEN];
    int activeTimer;
    int seconds;
    int count;
}t_Args;

/**
 * @brief Structure for storing information about headers
 * 
 */
typedef struct FlowHeader{
    int version;
    int count;
    char SysUptime[DATE_FORMAT]; // TODO
    int unix_secs;
    int unix_nsecs;
    int flow_sequence;
    int engine_type; //TODO
    int engine_id; // TODO
    int sampling_interval; // TODO
}t_FlowHeader;


/**
 * @brief Structure for storing information about flow
 * 
 */
typedef struct Flow{
    char src_IP[IP_LEN];
    char dst_IP[IP_LEN];
    char next_hop[IP_LEN];
    int input; //TODO
    int output; //TODO
    int dPkts;
    int dOctets;
    char first[DATE_FORMAT];
    char last[DATE_FORMAT];
    unsigned src_port;
    unsigned dst_port;
    int pad1; //TODO
    int prot;
    int tos; // TODO
    int src_as; //TODO
    int dst_as; //TODO
    int pad2; // TODO
    struct Flow *next;
    struct Flow *previous;
    struct FlowHeader *header;
}t_Flow;

/**
 * @brief Structure for storing user input arguments
 * 
 */
typedef struct List{
    t_Flow *head;
    t_Flow *last;
    int counter;
}t_List;

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
void process_tcp(const u_char *data ,int ip_header_len, unsigned *src_port, unsigned *dst_port);

/**
 * @brief Fucntion gets important information about UDP packet
 * 
 * @param data String containing packet data
 * @param ip_header_len Length of ip header
 */
void process_udp(const u_char *data, int ip_header_len, unsigned *src_port, unsigned *dst_port);

/**
 * @brief 
 * 
 */
void process_icmp();

// Tohle bude funkce na kontrolovani timeru flow (ktere odeslat)
void check_times();

t_FlowHeader *create_header();

void delete_header(t_FlowHeader *header);

t_Flow *create_flow(char *src_ip);

void delete_flow(t_Flow *flow);

t_List ctor_List();

void list_add(t_List *list, t_Flow *flow);

void list_delete(t_List *list, t_Flow *flow);

t_Flow *list_find();