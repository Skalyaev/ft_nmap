#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "define.h"
#include "struct.h"

void getargs(const int ac, char** const av);
const char* usage();

char** read_arg(char* const optarg);
char** read_file(const char* const file);

byte new_hosts(const char opt, char* const optarg);
byte new_ports(char* const optarg);
byte new_scans(char* const optarg);

void default_ports();
void default_scans();

uint get_host_ip();
void ip_hdr(t_iphdr* const hdr, const ubyte protocol,
            const uint saddr, const uint daddr);

byte tcp_probe(const char* const dst_host, const ushort dst_port,
               const char** const flags);

ushort checksum(const ushort* ptr, const ubyte nbytes);
t_socket new_socket(const char* const host, const ushort port,
                    const int protocol);

byte new_probe(t_socket* const sock,
               t_iphdr* const iphdr,
               const ushort size,
               byte* const payload,
               byte* const recv_buff);

void sigexit(const int sig);
byte bye();

#endif
