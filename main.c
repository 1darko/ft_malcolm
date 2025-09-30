#include "malcolm.h"

/*
◦ sendto - send data
◦ recvfrom - receive data

◦ socket - create a socket
◦ setsockopt - set socket options

◦ inet_pton - transform IPv4/IPv6 addresses to binary form
◦ inet_ntop - transform binary IP addresses to text form
◦ inet_addr - convert IPv4 addresses from text to binary form

◦ if_nametoindex - get interface index from name ??????
◦ sigaction - examine and change signal action
◦ signal - set a signal handler
◦ gethostbyname - get host information by name
◦ getaddrinfo, freeaddrinfo - get address information
◦ getifaddrs, freeifaddrs - get interface addresses
◦ htons, ntohs - convert port numbers between host and network byte order
◦ strerror / gai_strerror - get string representation of error codes

◦ getuid - get ID, check for root
◦ close - close a socket
◦ sleep - sleep

◦ printf and its family - printers
*/

int main(int ac, char **av) 
{
    printf("Hello\n");
    if(ac == 1)
    {
        printf("Args needed\n");
        return 1;
    }
    if(getuid() != 0)
    {
        printf("Root privilage needed\n");
        return(1);
    }
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) 
    {
        printf("socket");
        return 1;
    }
    uint8_t buf1[2048];
    // Add signal handler to close and exit on Ctrl+C
    // while(1)
    // {
    recvfrom(sock, buf1, sizeof(buf1), 0, NULL, NULL);
    printf("Packet received, size %zd\n", sizeof(buf1));
    ether_hdr *eth = (ether_hdr *)buf1;
    // printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dest_addr[0], eth->dest_addr[1], eth->dest_addr[2], eth->dest_addr[3], eth->dest_addr[4], eth->dest_addr[5]);
    // printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src_addr[0], eth->src_addr[1], eth->src_addr[2], eth->src_addr[3], eth->src_addr[4], eth->src_addr[5]);
    // printf("Frame type: 0x%04x\n", ntohs(eth->frame_type));
    arp_ether_ipv4 *arp = (arp_ether_ipv4 *)(buf1 + sizeof(eth));
    if (ntohs(arp->op) == 1) // ARP request
    {
        printf("ARP Request:\n");
        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
        printf("Sender IP: %d.%d.%d.%d\n", (arp->spa >> 24) & 0xFF, (arp->spa >> 16) & 0xFF, (arp->spa >> 8) & 0xFF, arp->spa & 0xFF);
        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
        printf("Target IP: %d.%d.%d.%d\n", (arp->tpa >> 24) & 0xFF, (arp->tpa >> 16) & 0xFF, (arp->tpa >> 8) & 0xFF, arp->tpa & 0xFF);
    };
    //
    close(sock);
    // exit(0);
    // }
    return 0;
}