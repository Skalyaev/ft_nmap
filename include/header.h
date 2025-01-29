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
void sigexit(const int sig);
byte bye();

t_socket* sock_raw(const char* const host,
                   const ushort port,
                   const int proto);

t_iphdr ip_hdr(const uint* saddr,
               const uint daddr,
               const ubyte proto)

byte tcp_probe(const char* const host,
               const ushort port,
               const char** const flags)
#endif
