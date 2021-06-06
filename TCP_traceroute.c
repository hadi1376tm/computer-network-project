#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

int UNUSED_PORT;
int SOCKET_TIMEOUT;
int RECV_BUF_LEN;
int MAX_TTL;
int MIN_TTL;
int Hop_Attempts;
int input_max_tll;
int input_min_tll;
int input_time;
int input_RECV_BUF_LEN;
int input_Hop_Attempts;
int input_UNUSED_PORT;

typedef enum{true,false} bool;
int main (int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <IP address> or <URL>\n ", argv[0]);
        exit(-1);
    }

    char *trace_dest = argv[1];

    // Get current IP
    struct sockaddr_in *src_addr;
    struct ifaddrs *id, *id_tmp;
    int getAddress = getifaddrs(&id);
    if (getAddress == -1)
    {
        perror("Unable to retrieve IP address of interface");
        exit(-1);
    }
    
    printf("Enter an unused port (recommend:2468) : ");
    scanf("%d",&input_UNUSED_PORT);
    UNUSED_PORT= input_UNUSED_PORT;
    
    printf("Enter start TTL (min=0) : ");
    scanf("%d",&input_min_tll);
    MIN_TTL= input_min_tll;
    
    printf("Enter last TTL : ");
    scanf("%d",&input_max_tll);
    MAX_TTL= input_max_tll;

    printf("Enter Socket Timeout(s) : ");
    scanf("%d",&input_time);
    SOCKET_TIMEOUT= input_time;
    
    printf("Enter Packet Lenth : ");
    scanf("%d",&input_RECV_BUF_LEN);
    RECV_BUF_LEN= input_RECV_BUF_LEN;
    
    printf("number of re_try attemps to connect a hop : ");
    scanf("%d",&input_Hop_Attempts);
    Hop_Attempts= input_Hop_Attempts;
    printf("     ***********\n ");
    
    id_tmp = id;
    while (id_tmp) 
    {
        if ((id_tmp->ifa_addr) && (id_tmp->ifa_addr->sa_family == AF_INET))
        {
            src_addr = (struct sockaddr_in *) id_tmp->ifa_addr;
        }
        id_tmp = id_tmp->ifa_next;
    }
    printf("Traceroute from host: %s\n", inet_ntoa(src_addr->sin_addr));

    // Resolve destination IP
    struct sockaddr_in dest_addr; 
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(UNUSED_PORT);

    int is_ip_addr = inet_pton(AF_INET, trace_dest, &(dest_addr.sin_addr));
    if (!is_ip_addr)
    {
        struct hostent *host;
        host = gethostbyname(trace_dest);
        if (host == NULL)
        {
            perror("Invalid host or failed DNS resolution");
            exit(-1);
        }

        dest_addr.sin_addr = *((struct in_addr *)host->h_addr);
        printf("[DNS resolution] %s resolved to %s\n",
                trace_dest,
                inet_ntoa(dest_addr.sin_addr));

    }

    // create socket to send tcp messages
    int sendSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (sendSocket < 0)
    {
        perror("Error creating tcp socket");
        exit(-1);
    }

    // create socket to receive icmp messages
    int recvSocket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recvSocket < 0)
    {
        perror("Error creating icmp socket");
        exit(-1);
    }

    // set timeout 
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT;

    int setTimeoutOptTcp = setsockopt(sendSocket, SOL_SOCKET, SO_SNDTIMEO,
            (struct timeval *)&timeout, sizeof(struct timeval));
    if (setTimeoutOptTcp < 0)
    {
        perror("Error setting socket timeout (tcp)");
        exit(-1);
    }

    int setTimeoutOptIcmp = setsockopt(recvSocket, SOL_SOCKET, SO_RCVTIMEO,
            (struct timeval *)&timeout, sizeof(struct timeval));
    if (setTimeoutOptIcmp < 0)
    {
        perror("Error setting socket timeout (icmp)");
        exit(-1);
    }

    // receive buffer
    char recvBuffer[RECV_BUF_LEN];
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(struct sockaddr_in);
    long numBytesReceived;

    printf("--------------- traceroute results ---------------\n");
    printf("%d: %s [start]\n",MIN_TTL ,inet_ntoa(src_addr->sin_addr));
    int i = MIN_TTL;
    int j = 0;
    bool failed_hop = false;
    while (i < MAX_TTL)
    {   
        failed_hop= false;
        j=0;
        i++;
        do {
        j++;
        // set TTL in IP header
        setsockopt(sendSocket, IPPROTO_IP, IP_TTL, &i, sizeof(i));

        // send SYN packet (start 3-way handshake)
        errno = 0;
        connect(
                sendSocket,
                (struct sockaddr *)&dest_addr,
                sizeof(struct sockaddr));

        int icmpErrorReceived = 0;

        // TTL expired
        if (errno == EHOSTUNREACH)
        {
            while (!icmpErrorReceived)
            {
                numBytesReceived = recvfrom(
                        recvSocket,
                        recvBuffer,
                        RECV_BUF_LEN,
                        0,
                        (struct sockaddr *)&cli_addr,
                        &cli_len);

                // extract IP header
                struct ip *ip_hdr = (struct ip *)recvBuffer;

                // extract ICMP header
                int ipHeaderLength = 4 * ip_hdr->ip_hl;
                struct icmp *icmp_hdr =
                    (struct icmp *)( (char*) ip_hdr + ipHeaderLength );

                int icmpMessageType = icmp_hdr->icmp_type;
                int icmpMessageCode = icmp_hdr->icmp_code;


                // TTL exceeded
                if (icmpMessageType == ICMP_TIME_EXCEEDED
                        && icmpMessageCode == ICMP_NET_UNREACH)
                {
                    // check if ICMP messages are related to TCP SYN packets
                    struct ip *inner_ip_hdr = 
                        (struct ip *)( (char*) icmp_hdr + ICMP_MINLEN);
                    if (inner_ip_hdr->ip_p == IPPROTO_TCP)
                    {
                        icmpErrorReceived = 1;
                    }
                }

                // port unreachable
                else if (icmpMessageType == ICMP_DEST_UNREACH
                        && icmpMessageCode == ICMP_PORT_UNREACH)
                {
                    printf("%d: %s [complete]\n", 
                            i, inet_ntoa(dest_addr.sin_addr));
                    printf("port unreachable\n");
                    printf("--------------- traceroute terminated ---------------\n");
                    exit(0);
                }
            }
            printf("%d: %s\n", i, inet_ntoa(cli_addr.sin_addr));
            failed_hop = false;
            // timeout
        } else if (
                errno == ETIMEDOUT      // socket timeout
                || errno == EINPROGRESS // operation in progress
                || errno == EALREADY    // consecutive timeouts
                )
        {
            failed_hop = true;
            if (j<  Hop_Attempts+1){
            printf("%d: hop failed :retrying (%d)\n", i, j);
            }
            else{
               printf("%d: hop FAILED *****\n", i); 
            }
        }

        // case: destination reached
        else if (errno == ECONNRESET || errno == ECONNREFUSED)
        {
            printf("%d: %s [complete]\n", 
                    i, inet_ntoa(dest_addr.sin_addr));
             printf("trace was SUCCESSFULL\n");
            printf("--------------- traceroute terminated ---------------\n");
            exit(0);
        }
        else
        {
            printf("Unknown error: %d sending SYN packet\n", errno);
            exit(-1);
        }
    }while(j < Hop_Attempts+1 && failed_hop == true);
}
    printf("Unable to reach host within TTL of %d\n", MAX_TTL); 
    printf("--------------- traceroute terminated ---------------\n");
    return -1;
}

// Resolves the reverse lookup of the hostname
char* reverse_dns_lookup(char *ip_addr){
    struct sockaddr_in temp_addr;
    socklen_t len;
    char buf[NI_MAXHOST], *ret_buf;

    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *) &temp_addr, len, buf,
                    sizeof(buf), NULL, 0, NI_NAMEREQD)){
        printf("Could not resolve reverse lookup of hostname\n");
        return NULL;
    }
    ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char) );
    strcpy(ret_buf, buf);
    return ret_buf;
}


