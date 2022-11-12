// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// Header file for flow.c and all his modules

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <time.h>
#include <err.h>

#define ARG_LEN 4097 // Max len of filepath + zero sign
#define DEFAULT_COUNT 1024
#define DEFAULT_INACTIVE 10
#define DEFAULT_ACTIVE 60
#define DEFAULT_COLLECTOR_IP "127.0.0.1"
#define DEFAULT_COLLECTOR_PORT 2055
#define FILTER "udp or tcp or icmp"
#define FILTER_LEN 30
#define NUMBER_PACKETS 0
#define IP_LEN 2049 // Max len of url + zero sign
#define PORT_LEN 6

// Protocol numbers
#define ICMP 1
#define TCP 6
#define UDP 17

// NetFlow parametres
#define VERSION 5
#define COUNT 1

// Second formats
#define MILISECONDS 1000
#define MIKROSECONDS 1000000

// Packet sizes
#define HEADER_SIZE 24
#define FLOW_SIZE 48
#define PACKET_SIZE HEADER_SIZE + FLOW_SIZE // -> 72 (We are sending one flow per packet)

// TCP flags
#define FIN 1
#define RST 4

/**
 * @brief Structure for storing user input arguments
 * 
 */
typedef struct Args{
    char fileName[ARG_LEN];
    struct sockaddr_in collector;
    uint64_t activeTimer;
    uint64_t inactiveTimer;
    int count;
    struct hostent *servent;
    int sock;
}t_Args;

/**
 * @brief Structure for storing information about flow
 * 
 */
typedef struct Flow{
    uint32_t src_IP;
    uint32_t dst_IP;
    uint32_t dPkts;
    uint32_t dOctets;
    uint64_t first_sys;
    uint64_t last_sys;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tpc_flags;
    uint8_t prot;
    uint8_t tos;
    struct Flow *next;
    struct Flow *previous;
}t_Flow;

/**
 * @brief Structure for storing information about packet sending flow
 * 
 */
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

/**
 * @brief List structure for holding flows
 * 
 */
typedef struct List{
    t_Flow *head;
    t_Flow *last;
    int counter;
}t_List;


typedef struct timeval t_time;

//------------------- arguments.c ------------------- //

/**
 * @brief Constructor for argument structure
 * 
 * @return t_Args Rerturns allocated argument
 */
t_Args *ctor_Args();

/**
 * @brief Function prints help instruction on stdout
 * 
 */
void help_function();

/**
 * @brief Function splits input collector into ip address and port number
 * 
 * @param arg Argument to be splitted
 * @param ip String to store ip address to
 * @param port String to store port number to
 */
void split_arg(char *arg, char *ip, char *port);

/**
 * @brief Function for parsing and storing arguments
 * 
 * @param argc Number of input arguments
 * @param argv String array of input arguments
 */
void parse_arguments(int argc, char **argv, t_Args *args);

//------------------- flow.c ------------------- //

/**
 * @brief Callback function used for handling recieved packets
 * 
 * @param arguments User arguments -> NULL for our project
 * @param packet_header Packet header storing packet information
 * @param data String containing packet data
 */
void callback(u_char *arguments, const struct pcap_pkthdr *packet_header, const u_char *data);

/**
 * @brief Fucntion gets important information about TCP packet
 * 
 * @param data String containing packet data
 * @param ip_header_len Length of ip header
 */
void process_tcp(const u_char *data ,int ip_header_len, uint16_t *src_port, uint16_t *dst_port, uint8_t *tpc_flags);

/**
 * @brief Fucntion gets important information about UDP packet.
 * 
 * @param data String containing packet data
 * @param ip_header_len Length of ip header
 */
void process_udp(const u_char *data, int ip_header_len, uint16_t *src_port, uint16_t *dst_port);

/**
 * @brief Fucntion checks timers of flows.
 * If flow timer is completed, it sends flow to collector.
 * 
 */
void check_timers();

/**
 * @brief Creates new flow and adds it to the list of flows.
 * 
 * @param src_ip Source ip address 
 * @param dst_ip Destination ip address 
 * @param src_port Source port number 
 * @param dst_ip Destination port number 
 * @param type Type of protocol
 * @param octets Total number of L3 bytes in packet
 * @param tos Type of service
 * @param tcp_flags TCP flag of packet
 */
t_Flow *create_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type, uint32_t octets, uint8_t tos, uint8_t tcp_flags);

/**
 * @brief Updates flow information
 * 
 * @param flow Flow to be updated
 * @param octets Number of L3 bytes in packet to be added
 * @param tcp_flags TCP flag to be ORed
 */
void update_flow(t_Flow *flow, uint32_t add_octets, uint8_t tcp_flags);

/**
 * @brief Deletes flow
 * 
 * @param flow Flow to be deleted
 */
void delete_flow(t_Flow *flow);

//------------------- list.c ------------------- //

/**
 * @brief Creator for list.
 * 
 */
t_List ctor_List();

/**
 * @brief Adds flow to the list.
 * 
 * @param list List of flows
 * @param flow Flow to be added
 */
void list_add(t_List *list, t_Flow *flow);

/**
 * @brief Deletes flow from the list.
 * 
 * @param list List of flows
 * @param flow Flow to be deleted
 */
void list_delete(t_List *list, t_Flow *flow);

/**
 * @brief Tries to find the flow in the list based on given parametres.
 * 
 * @param list List of flows
 * @param flow Flow to be added
 * @param src_ip Source ip address 
 * @param dst_ip Destination ip address 
 * @param src_port Source port number 
 * @param dst_ip Destination port number 
 * @param type Type of protocol
 */
t_Flow *list_find(t_List *list, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type);

//------------------- sender.c ------------------- //

/**
 * @brief Sends flow to the collector.
 * 
 * @param flow Flow we want to send
 * @param oldest Sysup time of oldest (boot) packet
 * @param current Sysup time of current packet
 */
void send_flow(t_Args *args, t_Flow *flow, t_time *oldest, t_time *current);

/**
 * @brief Creates socket for client.
 * 
 * @param args Input arguments
 */
void create_client_sock(t_Args *args);

/**
 * @brief Connects to socket.
 * 
 * @param args Input arguments
 */
void connect_to_sock(t_Args *args);

/**
 * @brief Closes to socket.
 * 
 * @param args Input arguments
 */
void close_sock(t_Args *args);

//------------------- time.c ------------------- //

/**
 * @brief Gets sysup time, which is interval from boot time to current time.
 * 
 * @param oldest Epoch time in boot
 * @param current Epoch time of currently processed packet
 */
uint64_t get_SysUpTime(t_time *oldest, t_time *current);