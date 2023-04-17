// FILE: ipk-sniffer.h
// AUTHOR: xzavad20
// DESC: Network analyzer, captures and filters packets on a specific network interface

#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <signal.h>

#define OK 0
#define ERROR 1
#define MAC_ADDR_LEN 18
#define LINE_BYTES 16

// Struct for command line arguments
struct FlagsT {
    bool interface_defined;
    char *interface;
    bool port_defined;
    int port;
    bool tcp_defined;
    bool udp_defined;
    bool arp_defined;
    bool icmp4_defined;
    bool icmp6_defined;
    bool igmp_defined;
    bool mld_defined;
    bool num_defined;
    int num;
    bool ndp_defined;
};

pcap_t *pcap_handle = NULL;

// Function prototypes

// Handler for SIGINT
void sigint_handler(int sig);

// Displays all available interfaces
void show_interfaces(void);

// Parses command line arguments
void parse_input(int argc, char **argv, struct FlagsT *flags, char *protocol_filter);

// Displays packet timestamp
void display_timestamp(const struct pcap_pkthdr *header);

// Displays packet MAC addresses
void display_mac_addrs(char *src_mac_addr, char *dest_mac_addr, struct ether_header *eth_header);

// Displays packet payload data
void display_data(const struct pcap_pkthdr *header, const u_char *packet);

// Process packet and display its data
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Opens interface for packet capturing and filtering
pcap_t *pcap_handle_ctor(char *interface, char *protocol_filter);

// Checks if data link type is Ethernet
int check_datalink_header(pcap_t *handle);

#endif