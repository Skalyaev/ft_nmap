#ifndef PING_H

# define PING_H
# define _GNU_SOURCE

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <errno.h>
# include <netdb.h>

# define ICMP_ECHO 8
# define TIMEOUT_SEC 1

typedef enum s_debug {
	NONE,
	LOW,
	MEDIUM,
	HIGH
}	t_debug;

# define DEBUG_LEVEL HIGH

typedef enum s_host_status { 
	HOST_DOWN,
	HOST_UP
}	t_host_status;

typedef struct s_host_info {
	char *host;
	t_host_status status;
}	t_host_info;

typedef struct s_pseudo_header {
    u_int32_t src;
    u_int32_t dst;
    u_int8_t zero;
    u_int8_t proto;
    u_int16_t len;
} t_pseudo_header;

//Utils
unsigned short checksum(void *b, int len);

//ICMP
t_host_status icmp_probe(const char *ip);

//TCP
//t_host_status send_tcp_request(const char *ip);

#endif