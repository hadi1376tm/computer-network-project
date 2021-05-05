#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <float.h>
#include <assert.h>
#include <pthread.h>

#define DEFAULT_TTL 64;
#define RECV_TIMEOUT 1
#define PING_SLEEP_Time 1


int ttl = 120;
int packet_size = 100;
bool pinging = true;
char *ip_address;
double min_rtt = 9999999999999999.0, max_rtt = 0;

/
struct ping_pkt
{
    struct icmphdr header;
    char *message;
};
struct thread_args
{
    int ping_sockfd;
    struct sockaddr_in *ping_addr;
    char *ping_ip;
};

int create_socket();
struct in_addr **dns_lookup(char *, struct hostent *);
unsigned short checksum(void *, int);
void *send_ping(void *);

void intHandler(int dummy);

int main(int argc, char *argv[])
{
    //catching interrupt
    signal(SIGINT, intHandler);


    struct hostent host;
    struct in_addr **ip_list = dns_lookup(argv[1], &host);
    if (ip_list == NULL)
    {
        printf("Resolving failed.\n");
        return 0;
    }

    printf("addresses: \n");
    int i;
    for (i = 0; ip_list[i] != NULL; i++)
    {
        printf("%s ", inet_ntoa(*ip_list[i]));
        printf("\n");
    }
    int threads_number = i;

    pthread_t *pthreadArray = malloc(sizeof(pthread_t) * threads_number);
    for (i = 0; i < threads_number; i++)
    {
        struct sockaddr_in server_address;
        server_address.sin_family = host.h_addrtype;
        server_address.sin_addr.s_addr = *(long *)ip_list[i];

        int sockfd = create_socket();
        if (sockfd == -1)
        {
            printf("Socket creating failed.\n");
            free(pthreadArray);
            exit(EXIT_FAILURE);
        }
        
        ip_address = (char *)malloc(NI_MAXHOST * sizeof(char));
        strcpy(ip_address, inet_ntoa(*(struct in_addr *)ip_list[i]));

        struct thread_args *args_p = malloc(sizeof(struct thread_args));
        args_p->ping_sockfd = sockfd;
        args_p->ping_addr = &server_address;
        args_p->ping_ip = ip_address;

        printf("Host<%s> added\n", ip_address);
        pthread_create(&pthreadArray[i], NULL, send_ping, args_p);
    }
    for (i = 0; i < threads_number; i++)
    {
        int result_code = pthread_join(pthreadArray[i], NULL);
        assert(!result_code);
    }
    return 0;
}


struct in_addr **dns_lookup(char *addr_host, struct hostent *host)
{
    struct in_addr **addr_list;

    if ((host = gethostbyname(addr_host)) == NULL)
    {
        
        printf("geting host by name failed"); 
        return NULL;
    }

    addr_list = (struct in_addr **)host->h_addr_list;
    return addr_list;
}


int create_socket(){
    int fd; // file descriptor

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
    {
        perror("socket failed.");
        return fd;
    }

    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    
    return fd;
}


void *send_ping(void *args)
{
    struct thread_args *args_p = (struct thread_args *)args;
    int ping_sockfd = args_p->ping_sockfd;
    struct sockaddr_in *ping_addr = args_p->ping_addr;
    char *ping_ip = args_p->ping_ip;
    int message_count = 0, i, addr_len, message_received_count = 0;
    bool packet_sent = true;
    struct ping_pkt packet;
    struct sockaddr_in recv_addr;
    struct timespec time_start, time_end;
    double rtt = 0;

    // infinite loop
    while (pinging)
    {
        bzero(&packet, sizeof(packet));
        packet_sent = true;

        packet.header.type = ICMP_ECHO;
        packet.header.un.echo.id = getpid(); 
        packet.message = (char *)malloc((packet_size - sizeof(struct icmphdr)) * sizeof(char));

        // filling packet
        for (i = 0; i < sizeof(packet.message) - 1; i++){
            packet.message[i] = i%5 + '0';
        }
        packet.message[i] = 0;
        packet.header.un.echo.sequence = message_count++;
        packet.header.checksum = checksum(&packet, sizeof(packet));

        sleep(PING_SLEEP_Time);

    
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        //send packet
        if (sendto(ping_sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)ping_addr, sizeof(*ping_addr)) == -1)
        {
            packet_sent = false;
            printf("sending failed.\n");
        }

        addr_len = sizeof(recv_addr);
        //receive packet
        if (recvfrom(ping_sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&recv_addr, &addr_len) <= 0 &&
            message_count > 1)
        {
            printf("reciving failed!\n");
        }
        else
        {
            // calculating RTT
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
            rtt = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

            
            if (packet_sent)
            {
                if (pinging)
                {
                    if ((packet.header.type == 69 && packet.header.code == 0))
                    {
                        printf("Reply from IP<%s> in %f ms seq=%d.\n", ping_ip, rtt, message_count);
                        message_received_count++;
                        if (rtt < min_rtt)
                            min_rtt = rtt;
                        if (rtt > max_rtt)
                            max_rtt = rtt;
                    }
                    else
                    {
                        printf("Error ICMP type %d, code %d\n", packet.header.type, packet.header.code);
                    }
                }
                
            }
        }
    }
    if (message_received_count > 0)
    {
        float packet_loss = ((message_count - message_received_count) / (float)message_count) * 100.0;
        printf("for IP<%s> <%d> packet(s) sent and <%d> packet(s) received, packet_loss = %f%%.\n", ping_ip, message_count, message_received_count, packet_loss);
    }
    return NULL;
}

// Calculate checksum bit
unsigned short checksum(void *b, int len)
{
    unsigned short *buffer = b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2)
        sum += *buffer++;

    if (len == 1)
        sum += *(unsigned char *)buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}


void intHandler(int dummy)
{
    printf("\n----------statistics----------\n");
    printf("MINIMUM RTT=<%f>ms MAXIMUM RTT=<%f>ms.\n", min_rtt, max_rtt);
    pinging = false;
}
