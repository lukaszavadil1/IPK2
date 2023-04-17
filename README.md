# **IPK Project 2 ZETA - Packet sniffer**

Network analyzer for capturing and filtering packets on a specific network interface

## **Introduction**

This program is a network analyzer for capturing and filtering packets on a specific network interface. It can capture and display packets of the following protocols: ARP, ICMPv4, ICMPv6, IGMP, MLD, NDP, TCP and UDP. It can also filter packets by port number and protocol.

## **Libraries**

This program uses the following libraries:

### **Standard C libraries**
- *stdio.h* - for input/output
- *stdlib.h* - for standard library functions
- *string.h* - for string functions
- *stdbool.h* - for boolean type
- *ctype.h* - for character functions
- *time.h* - for time functions
- *signal.h* - for SIGINT handling

### **Libraries from libpcap**
- *pcap.h* - main library for capturing and processing packets
- *netinet/in.h* - for IPv4 and IPv6 addresses
- *netinet/if_ether.h* - for Ethernet addresses
- *netinet/ip.h* - for IPv4 header
- *netinet/ip6.h* - for IPv6 header
- *netinet/tcp.h* - for TCP header
- *netinet/udp.h* - for UDP header
- *arpa/inet.h* - for converting IP addresses to strings

## **Code structure**

The structure could be divided into four main parts:

- ### **Parsing arguments**
- ### **Opening interface**
- ### **Capturing packets**
- ### **Printing packets info**

### **Parsing arguments**

First the program parses command line arguments and stores them in the structure FlagsT. The structure contains the following fields:

```c
struct FlagsT {
    bool interface_defined;
    char *interface; // interface name
    bool port_defined;
    int port; // port > 0 && port < 65536
    bool tcp_defined;
    bool udp_defined;
    bool arp_defined;
    bool icmp4_defined;
    bool icmp6_defined;
    bool igmp_defined;
    bool mld_defined;
    bool num_defined;
    int num; // num > 0
    bool ndp_defined;
};
```

During the process it is also building a packet filter string that will be used to filter packets in the next step. All of this is done in the function parse_input: 

```c
void parse_input(int argc, char **argv, struct FlagsT *flags, char *protocol_filter);
```

### **Opening interface**

After parsing the arguments, the program opens the interface and starts capturing packets. Device IP address and netmask are obtained using pcap_lookupnet. Then the program opens the interface using pcap_open_live. After that it runs pcap_compile to compile the packet filter string and pcap_setfilter to set the filter. All of this is done in the function pcap_handle_ctor which returns a pointer to the constructed pcap handle.

Disclaimer: Most of the code in this function is taken from this website: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/

```c
pcap_t *pcap_handle_ctor(char *interface, char *protocol_filter);
```

### **Capturing packets**

When the pcap handle is constructed, the program checks if the data link type is Ethernet and then starts capturing packets. It uses pcap_loop function to capture packets. The function pcap_loop takes a callback function as an argument. The callback function is called for each captured packet and is defined in the function handle_packet.

```c
int check_datalink_header(pcap_t *handle);
```

### **Printing packets info**

Inside the callback function handle_packet, the program prints the following information about the packet:

- timestamp
- source MAC address
- destination MAC address
- frame length
- source IP address
- destination IP address
- source port (if TCP or UDP and port is specified)
- destination port (if TCP or UDP and port is specified)
- formatted payload data

The function handle_packet is defined as follows:

```c
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
```

Inside the function, the program first formats and displays timestamp from packet header, then does the same for MAC addresses and frame length. After that it checks if the packet is IPv4, IPv6 or ARP. Then it checks if the packet is TCP or UDP. Based on this it prints the source and destination IP addresses and ports. At the end it formats and prints the payload data.

```c
// Formats and prints timestamp
void display_timestamp(const struct pcap_pkthdr *header);
// Formats and prints MAC addresses
void display_mac_addrs(char *src_mac_addr, char *dest_mac_addr, struct ether_header *eth_header);
// Formats and prints payload data
void display_data(const struct pcap_pkthdr *header, const u_char *packet);
```

### **Other functions**

The program also contains the following functions:

```c
void show_interfaces(void); // Prints all available interfaces
void sigint_handler(int sig); // Handles SIGINT signal
```

## **Usage**
```
$ make
$ sudo ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [--ndp] {-n num}
```
## **Flags**
```
-i interface | --interface interface
```
Specifies the interface to capture packets from. If not specified or the program is executed without any flags, all available interfaces will be listed.
```
-p port [--tcp|-t] [--udp|-u]
```
Listens for packets on the specified port. Can't be used without specifying either --tcp/-t or --udp/-u or both.

### **What is TCP and UDP?**
TCP (Tranmission Control Protocol) is connection-oriented,reliable, and error-checked protocol that transfers stream of bytes on transport layer.

UDP (User Datagram Protocol) is connectionless, unreliable, and simple protocol that transfers datagrams on transport layer.

```
--arp
```
Filters ARP packets.

### **What is ARP?**

ARP (Address Resolution Protocol) is a protocol used to connect IP addresses with MAC addresses. It is used to find the MAC address of a device on a network when only its IP address is known.
```
--icmp4
```
Filters ICMPv4 packets.

### **What is ICMPv4?**
ICMPv4 (Internet Control Message Protocol) is a protocol used to send error messages and operational information between network devices.
```
--icmp6
```
Filters ICMPv6 packets.

### **What is ICMPv6?**
ICMPv6 analogous to ICMPv4, but for IPv6.
```
--igmp
```
Filters IGMP packets.

### **What is IGMP?**
IGMP (Internet Group Management Protocol) is a protocol that allows multiple devices to have the same IP address and receive the same data.
```
--mld
```
Filters MLD packets.

### **What is MLD?**
MLD (Multicast Listener Discovery) is a protocol that allows routers to discover multicast listeners on the network.
```
--ndp
```
Filters NDP packets.

### **What is NDP?**
NDP (Neighbor Discovery Protocol) is a protocol that help the communication between neighboring hosts in local network.

## **Execution examples with outputs**

### **Capture packet on interface enp0s3**
```
$ sudo ./ipk-sniffer -i enp0s3
```

Output format

```
2023-04-17T19:20:56.222+00:00
src MAC: 08:00:27:32:28:e0
dst MAC: 38:43:7d:a6:b4:07
frame length: 90 bytes
src IP: 192.168.0.249
dst IP: 34.123.33.186
src port: 60416
dst port: 443

0x0000: 38 43 7d a6 b4 07 08 00 27 32 28 e0 08 00 45 00  8C}.....'2(...E.
0x0010: 00 4c 0b 25 40 00 40 06 29 b1 c0 a8 00 f9 22 7b  .L.%@.@.)....."{
0x0020: 21 ba ec 00 01 bb 7f 09 21 4d b6 38 f4 f3 80 18  !.......!M.8....
0x0030: 01 f5 06 15 00 00 01 01 08 0a 94 1e d9 aa 81 0f  ................
0x0040: 70 7c 17 03 03 00 13 65 59 b5 cc dd bc 92 28 4e  p|.....eY.....(N
0x0050: 1a 89 df c7 92 da cf 91 e9 3d                    .........=
```

### **List all available interfaces**
```
$ sudo ./ipk-sniffer
```
or
```
$ sudo ./ipk-sniffer [-i | --interface]
```

Output format

```
Interface: enp0s3
Interface: any
Interface: lo
Interface: nflog
Interface: nfqueue
```

### **Capture 2 tcp packets on port 20 on interface enp0s3**
```
$ sudo ./ipk-sniffer -i enp0s3 -p 20 --tcp -n 2
```

Output format

```
2023-04-17T19:26:33.141+00:00
src MAC: 08:00:27:32:28:e0
dst MAC: 38:43:7d:a6:b4:07
frame length: 74 bytes
src IP: 192.168.0.249
dst IP: 20.189.173.10
src port: 33248
dst port: 443

0x0000: 38 43 7d a6 b4 07 08 00 27 32 28 e0 08 00 45 00  8C}.....'2(...E.
0x0010: 00 3c 2b d0 40 00 40 06 8b 83 c0 a8 00 f9 14 bd  .<+.@.@.........
0x0020: ad 0a 81 e0 01 bb 29 2f 63 06 00 00 00 00 a0 02  ......)/c.......
0x0030: fa f0 83 97 00 00 02 04 05 b4 04 02 08 0a b0 8b  ................
0x0040: f3 7b 00 00 00 00 01 03 03 07                    .{........

2023-04-17T19:26:33.380+00:00
src MAC: 38:43:7d:a6:b4:07
dst MAC: 08:00:27:32:28:e0
frame length: 66 bytes
src IP: 20.189.173.10
dst IP: 192.168.0.249
src port: 443
dst port: 33248

0x0000: 08 00 27 32 28 e0 38 43 7d a6 b4 07 08 00 45 00  ..'2(.8C}.....E.
0x0010: 00 34 2f 35 40 00 68 06 60 26 14 bd ad 0a c0 a8  .4/5@.h.`&......
0x0020: 00 f9 01 bb 81 e0 00 a2 e8 45 29 2f 63 07 80 12  .........E)/c...
0x0030: ff ff f3 05 00 00 02 04 05 8c 01 03 03 08 01 01  ................
0x0040: 04 02                                            ..
```

### **Capture arp or icmp4 or ndp packet on interface enp0s3**
```
$ sudo ./ipk-sniffer -i enp0s3 --arp --icmp4 --ndp
```

Output format

```
2023-04-17T19:28:57.068+00:00
src MAC: 38:43:7d:a6:b4:07
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 56 bytes
src IP: 192.168.0.1
dst IP: 192.168.0.101

0x0000: ff ff ff ff ff ff 38 43 7d a6 b4 07 08 06 00 01  ......8C}.......
0x0010: 08 00 06 04 00 01 38 43 7d a6 b4 07 c0 a8 00 01  ......8C}.......
0x0020: 00 00 00 00 00 00 c0 a8 00 65 00 00 00 00 00 00  .........e......
0x0030: 00 00 00 00 00 00 00 00                          ........
```

## **Testing**

Testing was done manually using application with similar functionality, Wireshark.
During testing, I captured packets from my home network and compared them with the output of my application. I also tried to raise the number of captured packets to 1000 and it worked without any problems and to identify as many edge cases as possible so the program would not crash without proper error message. 

## **Conclusion**

The application is able to capture defined amount of packets from specified available interface and filter them by protocol and port number. It is also able to list all available interfaces. I learned a lot about network protocols, packets and how to work with them. Even though it was a lot of work, I enjoyed it and I am satisfied with the result.

## **References**

- TCP - https://cs.wikipedia.org/wiki/Transmission_Control_Protocol

- UDP - https://www.techtarget.com/searchnetworking/definition/UDP-User-Datagram-Protocol

- ARP - https://www.javatpoint.com/address-resolution-protocol-and-its-types

- ICMP - https://www.fortinet.com/resources/cyberglossary/internet-control-message-protocol-icmp

- IGMP - https://www.cloudflare.com/learning/network-layer/what-is-igmp/

- MLD - https://kb.netgear.com/21991/What-is-Multicast-Listener-Discovery-MLD-and-how-does-it-work-with-my-managed-switch

- NDP - https://www.ionos.com/digitalguide/server/know-how/what-is-neighborhood-discovery-protocolndp/

- Opening interface - https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/