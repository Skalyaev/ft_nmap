#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

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

uint32_t get_host_ip();
void ip_hdr(t_iphdr* const hdr, const uint8_t protocol,
            const uint32_t saddr, const uint32_t daddr);

void tcp_hdr(t_tcphdr* const hdr, const char** const flags,
             const ushort src_port, const ushort dport);

byte tcp_probe(const char* const dst_host, const ushort dst_port,
               const char** const flags);

t_socket sock_raw(const char* const host, const ushort port,
                  const int protocol);

void sigexit(const int sig);
byte bye();

#endif
