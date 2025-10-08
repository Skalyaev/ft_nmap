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

#include <linux/filter.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include "define.h"
#include "struct.h"
#include "service.h"

// argument/parse.c
// ================
int8_t parse_args(const int ac, char** const av);

// argument/usage.c
// ================
void usage(const char* const name);

// argument/read.c
// ===============
char** read_arg(char* const arg);

char** read_file(const char* const path);

// argument/host.c
// ===============
int8_t new_hosts(const char opt, char* const arg);

// argument/port.c
// ===============
void default_ports();

int8_t new_ports(char* const arg);

// argument/scan.c
// ===============
void default_scans();

int8_t new_scans(char* const arg);

// tasklist.c
// ==========
int8_t build_tasklist();

t_task* get_next_task();

// task/host-discovery.c
// =====================
void host_discovery(const t_task* const task);

// task/os-detection.c
// ===================
void os_detection(const t_task* const task);

// task/port-scan.c
// ================
void port_scan(const t_task* const task);

// scan/syn.c
// ==========
int8_t syn_scan(const char* const dst_host,
                const uint16_t dst_port);

// scan/null.c
// ===========
int8_t null_scan(const char* const dst_host,
                 const uint16_t dst_port);

// scan/fin.c
// ==========
int8_t fin_scan(const char* const dst_host,
                const uint16_t dst_port);

// scan/xmas.c
// ===========
int8_t xmas_scan(const char* const dst_host,
                 const uint16_t dst_port);

// scan/ack.c
// ==========
int8_t ack_scan(const char* const dst_host,
                const uint16_t dst_port);

// scan/connect.c
// ==============
int8_t connect_scan(const char* const dst_host,
                    const uint16_t dst_port);

// scan/window.c
// =============
int8_t window_scan(const char* const dst_host,
                   const uint16_t dst_port);

// scan/maimon.c
// =============
int8_t maimon_scan(const char* const dst_host,
                   const uint16_t dst_port);

// scan/udp.c
// ==========
int8_t udp_scan(const char* const dst_host,
                const uint16_t dst_port);

// protocol/ip.c
// =============
int8_t valid_host(const char* const host);

int8_t get_src_ip();

void ip_hdr(t_iphdr* const hdr,
            const uint8_t protocol,
            const uint32_t src_ip,
            const uint32_t dst_ip);

// protocol/icmp.c
// ===============
int8_t icmp_probe(const char* const dst_host,
                  uint8_t* const recv_buff);

// protocol/udp.c
// ==============
int8_t udp_probe(const char* const dst_host,
                 const uint16_t dst_port,
                 uint8_t* const recv_buff);

// protocol/tcp.c
// ==============
int8_t tcp_probe(const char* const dst_host,
                 const uint16_t dst_port,
                 const uint8_t flags,
                 uint8_t* const recv_buff);

// socket.c
// ========
uint16_t checksum(const uint16_t* ptr, const uint8_t size);

t_socket new_socket(const char* const dst_host,
                    const uint16_t dst_port,
                    const int protocol);

int8_t new_probe(t_socket* const sock,
                 const uint8_t headers_size,
                 uint8_t* const send_buff,
                 uint8_t* const recv_buff,
                 const uint8_t protocol,
                 const uint16_t src_port,
                 const uint16_t dst_port);

uint16_t allocate_src_port();

// log/worker.c
// ============
void error(const char* const msg);

void* logger();

// log/intro.c
// ===========
void intro();

// log/outro.c
// ===========
void outro();

// log/service.c
// =============
void port_scan_services(t_scan* const result);

// log/conclusion.c
// ================
void port_scan_conclusion(t_scan* const result);

// exit.c
// ======
void setcode(const int8_t code);

int8_t getcode();

int8_t bye();

void sigexit(const int sig);

#endif
