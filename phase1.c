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


const int MAX_IP_STR_LEN = 17;
const int MAX_PORT_STR_LEN = 7;
const int MIN_PORT_NUMBER= 1;
const int MAX_WELLKNOWN_PORT_NUMBER= 1023;
const int MAX_PORT_NUMBER= 65353;

int recv_timeout = 2;
int send_timeout = 2;

void remove_cr(char*);
int socket_creation();
bool socket_connect(int, char*, uint16_t);
void range_port_scan(char* , int , int );
void try_conecting(char* , int);
void ask_options(char*);

int main(int args[])
{
    
    
    char hostname[MAX_IP_STR_LEN];

	//Get the IP to scan
	printf("Enter IP [x.x.x.x] : ");
	fgets(hostname, MAX_IP_STR_LEN, stdin);
    int input_time;
    remove_cr(hostname);
    
    printf("Enter recive/send timeout : ");
    scanf("%d",&input_time);
    recv_timeout= input_time;
    send_timeout= input_time;

	
    
	ask_options(hostname);
    
	return(0);
}


int socket_creation()
{
	int fd; // fileDescriptor
	struct timeval timeout;


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


bool socket_connect(int fileDescriptor, char *host, uint16_t port)
{
	
	struct sockaddr_in server_addr;

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(host);

	
	if (connect(fileDescriptor, (struct sockaddr *)&(server_addr), sizeof(struct sockaddr_in)) < 0)
	{

		return false;
	}

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
void range_port_scan(char *hostname , int start , int end){
    
    
	for (int i = start; i < end+1; i++)
	{
		try_conecting(hostname,i);

    }
}

void try_conecting(char* hostname , int port){
    int fd = socket_creation();
		if (socket_connect(fd, hostname, (uint16_t)port)) {
			printf("%s:%d is open\n",hostname, port);
		}
		else 
			printf("%s:%d is close\n",hostname, port);

		if (fd > 0)		
			close(fd);	
    
}

void ask_port_service(char* hostname){
    
	puts("select number of service you want:\n\n");
	puts("1) HTTP (80)\n");
    puts("2) TLS (443)\n");
    puts("3) SMPT(25)\n");
    puts("4) FTP(21)\n");
    puts("5) TELENET(23)\n");
    puts("6) SSH(22)\n");
    
    int choice;
    scanf("%d",&choice);
    
    switch(choice)
	{
		case 1:
			try_conecting(hostname,80);
			break;
        case 2:
			try_conecting(hostname,443);
			break;
        case 3:
			try_conecting(hostname,25);
			break;
        case 4:
			try_conecting(hostname,21);
			break;
        case 5:
			try_conecting(hostname,23);
			break;
        case 6:
			try_conecting(hostname,22);
			break;
        default:
			printf("input is not correct");
    }
    
}

void ask_options(char* hostname){

	puts("select one option number:\n\n");
	puts("1) scan all ports\n");
	puts("2) scan well_known ports(0-1023)\n");
	puts("3)scan specific port \n");
	puts("4)scan specific services\n");
	puts("5)scan specific range\n");

	
	int choice;
    scanf("%d",&choice);

	switch(choice)
	{
		case 1:
			range_port_scan(hostname,MIN_PORT_NUMBER,MAX_PORT_NUMBER );
			break;

		case 2:
			range_port_scan(hostname,MIN_PORT_NUMBER,MAX_WELLKNOWN_PORT_NUMBER );
			break;

		case 3:
        {
            int specific_port;
            printf("Enter port you want to be scanned : ");
            scanf("%d" , &specific_port);
            try_conecting(hostname,specific_port);
			break;
        }
		case 4:
			ask_port_service(hostname);
			break;
		case 5:
        {
            int port_start_range;
            int port_end_range;
            printf("Enter port start range : ");
            scanf("%d" , &port_start_range);
            printf("Enter port end range : ");
            scanf("%d" , &port_end_range);
			range_port_scan(hostname,port_start_range,port_end_range );
			break;
        }

		
		default:
			printf("input is not correct");
	}
	
}
