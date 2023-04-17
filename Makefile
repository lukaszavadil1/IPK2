all: ipk-sniffer.c
	gcc -Wall -Wextra -o ipk-sniffer ipk-sniffer.c -lpcap