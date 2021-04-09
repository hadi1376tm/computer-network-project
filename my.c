#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>

#define DEFAULT_SEND_TIMEOUT 2
#define DEFAULT_RECV_TIMEOUT 2


const int MAX_IP_STR_LEN = 17;
const int MAX_PORT_STR_LEN = 7;
const int MAX_MSG_OUT_LEN = 128;
const int MAX_HOSTNAME_LEN=100;
const int NUMBER_OF_SERVICES = 10;
const int MIN_PORT_NUMBER= 1;
const int MAX_WELLKNOWN_PORT_NUMBER= 1023;
const int MAX_PORT_NUMBER= 65353;
const int MAX_NUMBER_OF_THREADS = 7;

int16_t recv_timeout = DEFAULT_RECV_TIMEOUT;
int16_t send_timeout = DEFAULT_SEND_TIMEOUT;

void remove_cr(char*);
int socket_creation();
bool socket_connect(int, char*, uint16_t);
void ask_options(char*);

int main(int argc , char **argv)
{
    char hostname[MAX_IP_STR_LEN];

	//Get the hostname to scan
	printf("Enter IP [x.x.x.x] : ");
	fgets(hostname, MAX_IP_STR_LEN, stdin);
	remove_cr(hostname);
    
	ask_options(hostname);
    
	return(0);
}

// return fileDescriptor of created socket
int socket_creation()
{
	int fd; // fileDescriptor
	struct timeval timeout;

	// SOCK_STREAM related to TCP connection
	// 0 -> ANY
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
	{
		perror("socket() failed.");
		return fd;
	}

	timeout.tv_sec = recv_timeout;
	timeout.tv_usec = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt() failed.");
		if (fd > -1)
		{
			close(fd);
			fd = -1;
		}
	}

	timeout.tv_sec = send_timeout;
	timeout.tv_usec = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt() failed.");
		if (fd > -1)
		{
			close(fd);
			fd = -1;
		}
	}
	return fd;
}

// connect socket(fileDescriptor) to target_host:target_port
// out_errno is kinda output
bool socket_connect(int fileDescriptor, char *host, uint16_t port)
{
	// fileDescriptor -> socket
	struct sockaddr_in server_addr;

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(host);

	// printf("Connecting to %s:%d... ", host, port);
	if (connect(fileDescriptor, (struct sockaddr *)&(server_addr), sizeof(struct sockaddr_in)) < 0)
	{

		perror("connection failed.");
		return false;
	}
	// printf("Connection established %s:%d\n", host, port);

	return true;
}

void remove_cr(char* str){
    for(int i = 0; i < strlen(str); i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            return;
        }
    }
}
void range_port_scan(char *hostname){
    
    int port_start_range;
    int port_end_range;
    printf("Enter port start range : ");
    scanf("%d" , &port_start_range);
    printf("Enter port end range : ");
    scanf("%d" , &port_end_range);


	for (int i = port_start_range; i < port_end_range+1; i++)
	{
		int fd = socket_creation();
		if (socket_connect(fd, hostname, (uint16_t)i)) {
			printf("%s:%d is open\n",hostname, i);
		}
		else 
			printf("%s:%d is close\n",hostname, i);

		if (fd > 0)		
			close(fd);	
	}

}

void max_range_port_scan (char *hostname){
   
    

	for (int i = MIN_PORT_NUMBER; i < MAX_PORT_NUMBER+1; i++)
	{
		int fd = socket_creation();
		if (socket_connect(fd, hostname, (uint16_t)i)) {
			printf("%s:%d is open\n",hostname, i);
		}
		else 
			printf("%s:%d is close\n",hostname, i);

		if (fd > 0)		
			close(fd);	
	}

}

void ask_options(char* hostname){

	int choice;
	puts("select what you want:\n");
	puts("1-scan all ports\n");
	//puts("2-just for well-known ports(0-1023)\n");
	//puts("3-request for specific port \n");
	//puts("4-request for specific services\n");
	puts("5-request for specific range\n");

	choice = getchar();
	getc(stdin);

	choice -= '0';

	printf("you chose %d \n",choice);

	switch(choice)
	{
		case 1:
			max_range_port_scan (hostname);
			break;

		case 2:
			//scan_port_range(server_addr_str,MIN_PORT_NUMBER,MAX_WELLKNOWN_PORT_NUMBER);
			break;

		case 3:

			//input_and_scan_port(server_addr_str,port_str);
			break;
		case 4:
			//ask_port_service(server_addr_str,port_str);
			break;
		case 5:

			range_port_scan(hostname);
			break;


			// operator doesn't match any case constant +, -, *, /
		default:
			printf("Error! operator is not correct");
	}
	
}
