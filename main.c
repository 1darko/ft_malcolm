#include "malcolm.h"

/*
 sendto, recvfrom.
◦ socket, setsockopt.
◦ inet_pton, inet_ntop.
◦ if_nametoindex, sleep.
◦ getuid, close.
◦ sigaction, signal.
◦ inet_addr.
◦ gethostbyname.
◦ getaddrinfo, freeaddrinfo.
◦ getifaddrs, freeifaddrs.
◦ htons, ntohs.
◦ strerror / gai_strerror.
◦ printf and its family.
*/

int main(int ac, char **av) 
{
    if(ac == 1)
    {
        printf("Args needed\n");
        return 1;
    }
//     if(getuid() != 0)
//     {
//         printf("Root privilage needed\n");
//         return(1);
//     }
    struct in_addr tmp;
    printf("Ret inet_pton %d\n",inet_pton(AF_INET, av[1], &tmp));
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &tmp, buf, INET_ADDRSTRLEN);
    printf("Buf %s\n", buf);
    // free(buf);
    return 0;
}