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

int hex_check(char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
};

int mac_to_byte(char *mac_str, uint8_t mac_bytes[ETH_ALEN]){

    int i = 0;
    int high_bytes, low_bytes;
    while(*mac_str && i < ETH_ALEN)
    {
        high_bytes = hex_check(*mac_str++);
        if(high_bytes < 0) return 1;
        low_bytes = hex_check(*mac_str++);
        if(low_bytes < 0) return 1;
        mac_bytes[i++] = (high_bytes << 4) | low_bytes;
        if(*mac_str == ':' || *mac_str == '-')
            mac_str++;
    }
    return (i == ETH_ALEN && *mac_str == '\0') ? 0 : 1;
}
int reply_prep(reply_info **reply, char **av)
{
    reply_info *r = malloc(sizeof(*r));
    if(!r)
        return 2;
    r->op = htons(2);
    if (inet_pton(AF_INET, av[1], &r->target_IP) != 1)
        return (free(r),1);
    if (mac_to_byte(av[2], r->fake_MAC) != 0)
        return (free(r),1);
    if (inet_pton(AF_INET, av[3], &r->victim_IP) != 1)
        return (free(r),3);
    if (mac_to_byte(av[4], r->victim_MAC) != 0)
        return (free(r),3);
    *reply = r;
    return 0;
};
void error_printer(int check)
{
    if(check == 1)
        fprintf(stderr, "IP address not valid\n");
    if(check == 3)
        fprintf(stderr, "MAC address not valid\n");
    else
        fprintf(stderr, "reply malloc failed");
}
int main(int ac, char **av) 
{
    if(ac == 1)
    {
        fprintf(stderr, "Args needed\n");
        return 1;
    }
    reply_info *reply = NULL;
    int check = reply_prep(&reply, av); 
    if(check)
    {
        error_printer(check);
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

    arp_ether_ipv4 *arp = (arp_ether_ipv4 *)(buf1 + sizeof(eth));
    if (ntohs(arp->op) == 1) // ARP request
    {
        printf("arp->op before :%hu" ,ntohs(arp->op));
        arp->op = htons(2);
        printf("arp->op after : %hu", ntohs(arp->op));
        // printf("ARP Request:\n");
        // printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
        // printf("Sender IP: %d.%d.%d.%d\n", (arp->spa >> 24) & 0xFF, (arp->spa >> 16) & 0xFF, (arp->spa >> 8) & 0xFF, arp->spa & 0xFF);
        // printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
        // printf("Target IP: %d.%d.%d.%d\n", (arp->tpa >> 24) & 0xFF, (arp->tpa >> 16) & 0xFF, (arp->tpa >> 8) & 0xFF, arp->tpa & 0xFF);
    };
    //
    close(sock);
    // exit(0);
    // }
    return 0;
}