// FILE: ipk-sniffer.c
// AUTHOR: xzavad20
// DESC: Network analyzer, captures and filters packets on a specific network interface

#include "ipk-sniffer.h"

void sigint_handler(int sig) {
    fprintf(stderr, "Interrupted by SIGINT, gracefully exiting...\n");
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
    }
    exit(sig);
}

void show_interfaces(void) {
    pcap_if_t *interface = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_findalldevs(&interface, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldev: Interfaces display error %s\n", errbuf);
        exit(ERROR);
    }
    else {
        // Display available interfaces
        while(interface != NULL) {
            printf("Interface: %s\n", interface->name);
            interface = interface->next;
        }
        pcap_freealldevs(interface);
    }
}

void parse_input(int argc, char **argv, struct FlagsT *flags, char *protocol_filter) {
    memset(flags, 0, sizeof(struct FlagsT));
    if (argc == 1) {
        show_interfaces();
        exit(OK);
    }
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--interface") == 0)) {
            if (argc == 2 && i+1 >= argc) {
                show_interfaces();
                exit(OK);
            }
            if (++i < argc) {
                if (flags->interface_defined) {
                    fprintf(stderr, "Error: interface specified multiple times\n");
                    exit(ERROR);
                }
                flags->interface_defined = true;
                flags->interface = malloc(sizeof(char) * (strlen(argv[i]) + 1));
                if (flags->interface == NULL) {
                    fprintf(stderr, "Error: failed to allocate memory\n");
                    exit(ERROR);
                }
                strcpy(flags->interface, argv[i]);
            } 
            else {
                fprintf(stderr, "Error: missing interface name\n");
                exit(ERROR);
            }
        } 
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (flags->port_defined) {
                fprintf(stderr, "Error: port specified multiple times\n");
                exit(ERROR);
            }
            if (++i < argc) {
                char *endptr;
                long int port_num = strtol(argv[i], &endptr, 10);
                if (*endptr != '\0' || port_num < 0 || port_num > 65535) {
                    fprintf(stderr, "Error: invalid port number '%s'\n", argv[i]);
                    exit(ERROR);
                } 
                else {
                    flags->port = (int)port_num;
                }
                flags->port_defined = true;
            } 
            else {
                fprintf(stderr, "Error: missing port number\n");
                exit(ERROR);
            }
        } 
        else if (strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "-t") == 0) { 
            if (flags->tcp_defined) {
                fprintf(stderr, "Error: only one of -t or --tcp may be specified\n");
                exit(ERROR);
            }
            flags->tcp_defined = true; 
        }
        else if (strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "-u") == 0) { 
            if (flags->udp_defined) {
                fprintf(stderr, "Error: only one of -u or --udp may be specified\n");
                exit(ERROR);
            }
            flags->udp_defined = true; 
        }
        else if (strcmp(argv[i], "--arp") == 0) {
            if (flags->arp_defined) {
                fprintf(stderr, "Error: only one of -a or --arp may be specified\n");
                exit(ERROR);
            }
            flags->arp_defined = true;
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "arp ");
            }
            else {
                strcat(protocol_filter, "or arp ");
            }
        }
        else if (strcmp(argv[i], "--icmp4") == 0) { 
            if (flags->icmp4_defined) {
                fprintf(stderr, "Error: only one of -i or --icmp4 may be specified\n");
                exit(ERROR);
            }
            flags->icmp4_defined = true;
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "icmp ");
            }
            else {
                strcat(protocol_filter, "or icmp ");
            }
        }
        else if (strcmp(argv[i], "--icmp6") == 0) { 
            if (flags->icmp6_defined) {
                fprintf(stderr, "Error: only one of -i or --icmp6 may be specified\n");
                exit(ERROR);
            }
            flags->icmp6_defined = true; 
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "(icmp6[0] == 128 or icmp6[0] == 129) ");
            }
            else {
                strcat(protocol_filter, "or (icmp6[0] == 128 or icmp6[0] == 129) ");
            }
        }
        else if (strcmp(argv[i], "--igmp") == 0) { 
            if (flags->igmp_defined) {
                fprintf(stderr, "Error: only one of -i or --igmp may be specified\n");
                exit(ERROR);
            }
            flags->igmp_defined = true; 
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "igmp ");
            }
            else {
                strcat(protocol_filter, "or igmp ");
            }
        }
        else if (strcmp(argv[i], "--mld") == 0) {
            if (flags->mld_defined) {
                fprintf(stderr, "Error: only one of -i or --mld may be specified\n");
                exit(ERROR);
            }
            flags->mld_defined = true;
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "(icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp6[0] == 143) ");
            }
            else {
                strcat(protocol_filter, "or (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp6[0] == 143) ");
            }
        }
        else if (strcmp(argv[i], "--ndp") == 0) {
            if (flags->ndp_defined) {
                fprintf(stderr, "Error: only one of -i or --ndp may be specified\n");
                exit(ERROR);
            }
            flags->ndp_defined = true;
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "(icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137) ");
            }
            else {
                strcat(protocol_filter, "or (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137) ");
            }
        }
        else if (strcmp(argv[i], "-n") == 0) {
            if (flags->num_defined) {
                fprintf(stderr, "Error: only one of -n or --num may be specified\n");
                exit(ERROR);
            }
            if (++i < argc) {
                char *endptr;
                long int num_val = strtol(argv[i], &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Error: invalid number '%s'\n", argv[i]);
                    exit(ERROR);
                } 
                else {
                    if (num_val > 0) {
                        flags->num = (int)num_val;
                    }
                    else {
                        fprintf(stderr, "Number has to be greater than 0, received '%ld'\n", num_val);
                        exit(ERROR);
                    }
                    flags->num_defined = true;
                }
            } 
            else {
                fprintf(stderr, "Error: missing number\n");
                exit(ERROR);
            }
        } 
        else {
            fprintf(stderr, "Error: unknown flag '%s'\n", argv[i]);
            exit(ERROR);
        }
    }
    if (flags->port_defined == false) {
        if (flags->tcp_defined == true) {
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "tcp ");
            }
            else {
                strcat(protocol_filter, "or tcp ");
            }
        }
        if (flags->udp_defined == true) {
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "udp ");
            }
            else {
                strcat(protocol_filter, "or udp ");
            }
        }
    }
    else {
        char port_temp[7] = ""; 
        if (flags->tcp_defined == false && flags->udp_defined == false) {
            fprintf(stderr, "Error: When port is defined there must be either -t or -u\n");
            exit(ERROR);
        }
        if (flags->tcp_defined == true) {
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "(tcp port ");
                sprintf(port_temp, "%d) ", flags->port);
                strcat(protocol_filter, port_temp);
            }
            else {
                strcat(protocol_filter, "or (tcp port ");
                sprintf(port_temp, "%d) ", flags->port);
                strcat(protocol_filter, port_temp);
            }
        }
        if (flags->udp_defined == true) {
            if (strlen(protocol_filter) == 0) {
                strcat(protocol_filter, "(udp port ");
                sprintf(port_temp, "%d) ", flags->port);
                strcat(protocol_filter, port_temp);
            }
            else {
                strcat(protocol_filter, "or (udp port ");
                sprintf(port_temp, "%d) ", flags->port);
                strcat(protocol_filter, port_temp);
            }
        }
    }
    if (flags->tcp_defined == false && flags->udp_defined == false && flags->arp_defined == false && flags->icmp4_defined == false && flags->icmp6_defined == false && flags->igmp_defined == false && flags->mld_defined == false && flags->ndp_defined == false) {
        strcat(protocol_filter, "tcp or udp or arp or icmp or (icmp6[0] == 128 or icmp6[0] == 129) or igmp or (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp6[0] == 143) or (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)");
    }
    if (flags->num_defined == false) {
        flags->num = 1;
    }
}

void display_timestamp(const struct pcap_pkthdr *header) {
    // Timestamp from Ethernet packet header
    time_t timestamp = header->ts.tv_sec;
    // Convert timestamp to local time
    struct tm *tm_local = localtime(&timestamp);
    char formatted_ts[32];
    // Format timestamp to yyyy-mm-ddThh:mm:ss
    strftime(formatted_ts, 32, "%Y-%m-%dT%H:%M:%S", tm_local);
    sprintf(&formatted_ts[19], ".%03d", (int) header->ts.tv_usec / 1000);

    // Calculate time zone offset
    int tz_offset_hours = (tm_local->tm_gmtoff / 3600) % 24;
    int tz_offset_minutes = (tm_local->tm_gmtoff / 60) % 60;
    char tz_sign = (tm_local->tm_gmtoff >= 0) ? '+' : '-';
    // Format time zone to +-hh:mm
    sprintf(&formatted_ts[23], "%c%02d:%02d", tz_sign, tz_offset_hours, tz_offset_minutes);

    printf("%s\n", formatted_ts);
}

void display_mac_addrs(char *src_mac_addr, char *dest_mac_addr, struct ether_header *eth_header) {
    // Get MAC adresses from header
    snprintf(src_mac_addr, MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", eth_header->ether_shost[0], 
        eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    snprintf(dest_mac_addr, MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", eth_header->ether_dhost[0],
        eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf("src MAC: %s\n", src_mac_addr);
    printf("dst MAC: %s\n", dest_mac_addr);
}

void display_ip_addrs(const void *restrict src, const void *restrict dest) {
    printf("src IP: %s\n", (char *)src);
    printf("dst IP: %s\n", (char *)dest);
}

void display_data(const struct pcap_pkthdr *header, const u_char *packet) {
    unsigned int byte_offset = 0;
    int bytes_left_print, bytes_left;

    while (byte_offset < header->len) {
        bytes_left = header->len - byte_offset;
        if (bytes_left < LINE_BYTES) {
            bytes_left_print = bytes_left;
        }
        else {
            bytes_left_print = LINE_BYTES;
        }
        printf("0x%04x: ", byte_offset);
        for (int i = 0; i < bytes_left_print; i++) {
            printf("%02x ", packet[byte_offset + i]);
        }
        for (int j = 0; j < LINE_BYTES - bytes_left_print; j++) {
            printf("   ");
        }
        printf(" ");
        for (int k = 0; k < bytes_left_print; k++) {
            char c = packet[byte_offset + k];
            // Display printable characters
            if (isprint(c)) {
                printf("%c", c);
            } 
            else {
                printf(".");
            }
        }
        printf("\n");
        byte_offset += bytes_left_print;
    }
    printf("\n");
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char src_mac_addr[MAC_ADDR_LEN], dest_mac_addr[MAC_ADDR_LEN] = "";
    char src_ip_addr[INET_ADDRSTRLEN], dest_ip_addr[INET_ADDRSTRLEN] = "";
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    signal(SIGINT, sigint_handler);

    // Display timestamp
    display_timestamp(header);

    // Display mac addresses
    display_mac_addrs(src_mac_addr, dest_mac_addr, eth_header);

    // Display frame length
    printf("frame length: %d bytes\n", header->len);

    // Format the output based on protocol (IPv4 or IPv6 or ARP)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ipv4_header = (struct ip *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &ipv4_header->ip_src, src_ip_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipv4_header->ip_dst, dest_ip_addr, INET_ADDRSTRLEN);
        display_ip_addrs(src_ip_addr, dest_ip_addr);
        if (ipv4_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        } 
        else if (ipv4_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_ip_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dest_ip_addr, INET6_ADDRSTRLEN);
        display_ip_addrs(src_ip_addr, dest_ip_addr);
        if (ipv6_header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        } 
        else if (ipv6_header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &arp_header->arp_spa, src_ip_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &arp_header->arp_tpa, dest_ip_addr, INET_ADDRSTRLEN);
        display_ip_addrs(src_ip_addr, dest_ip_addr);
    }
    printf("\n");

    // Display payload data
    display_data(header, packet);
}

// SOURCE: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
pcap_t *pcap_handle_ctor(char *interface, char *protocol_filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // Get device source ip address and netmask
    if (pcap_lookupnet(interface, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Open the device for packet capturing
    pcap_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Convert filter expression to binary
    if (pcap_compile(pcap_handle, &bpf, protocol_filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(pcap_handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(pcap_handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "Error: pcap_setfilter() ... %s\n", pcap_geterr(pcap_handle));
        return NULL;
    }
    return pcap_handle;
}

int check_datalink_header(pcap_t *pcap_handle) {
    int datalink_type;
    if ((datalink_type = pcap_datalink(pcap_handle)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink(): Function execution error%s\n", pcap_geterr(pcap_handle));
        return ERROR;
    }
    if (datalink_type != DLT_EN10MB) {
        fprintf(stderr, "Unsupported data link type %d, needs to be Ethernet\n", datalink_type);
        return ERROR;
    }
    return OK;
}

int main(int argc, char **argv) {
    struct FlagsT flags;
    char protocol_filter[512] = "";
    pcap_t *pcap_handle;
    int datalink_type;
    parse_input(argc, argv, &flags, protocol_filter);
    pcap_handle = pcap_handle_ctor(flags.interface, protocol_filter);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error: pcap_handle_ctor() ... Function execution error\n");
        exit(ERROR);
    }
    signal(SIGINT, sigint_handler);
    if ((datalink_type = check_datalink_header(pcap_handle)) == ERROR) {
        exit(ERROR);
    }
    if (pcap_loop(pcap_handle, flags.num, handle_packet, NULL) != 0) {
        fprintf(stderr, "Error: pcap_loop() ... Function execution error\n");
        exit(ERROR);
    }
    pcap_close(pcap_handle);
    return OK;   
}