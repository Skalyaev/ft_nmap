#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include "define.h"
#include "struct.h"

// argument/usage.c
// ================
const char* usage();

// argument/parse.c
// ================
void get_args(const int ac, char** const av);

// argument/read.c
// ===============
char** read_arg(char* const arg);

char** read_file(const char* const path);

// argument/host.c
// ===============
int8_t new_hosts(const char opt, char* const arg);

// argument/ports.c
// ================
void default_ports();

int8_t new_ports(char* const arg);

// argument/scans.c
// ================
void default_scans();

int8_t new_scans(char* const arg);

// protocol/ip.c
// =============
uint32_t get_host_ip();

void ip_hdr(t_iphdr* const hdr,
            const uint8_t protocol,
            const uint32_t src_ip,
            const uint32_t dst_ip);

// protocol/tcp.c
// ==============
int8_t tcp_probe(const char* const dst_host,
                 const uint16_t dst_port,
                 const uint8_t flags);
// socket.c
// ========
uint16_t checksum(const uint16_t* ptr, const uint16_t size);

t_socket new_socket(const char* const dst_host,
                    const uint16_t dst_port,
                    const int protocol);

int8_t new_probe(t_socket* const sock,
                 t_iphdr* const iphdr,
                 const uint16_t send_size,
                 int8_t* const send_buff,
                 int8_t* const recv_buff);
// exit.c
// ======
void sigexit(const int sig);

int8_t bye();

#endif
