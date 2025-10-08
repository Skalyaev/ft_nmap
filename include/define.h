#ifndef DEFINE_H
#define DEFINE_H

#define BUFFER_SIZE 1024

#define MAX_HOSTS 512
#define MAX_PORTS 1024
#define MAX_THREADS 250

#define YES 1
#define NO 0

// EXIT CODES
// ==========
#define SUCCESS 0
#define FAILURE -1

// REQUESTS
// ========
#define REQ_TASK_INTERVAL 0.4 * 1000000
#define REQ_FRAGMENT_SIZE 8
#define REQ_FRAGMENT_INTERVAL 0.04 * 1000000
#define REQ_RETRIES 4
#define REQ_TIMEOUT 0.8 * 1000000

// TASKS
// =====
#define TASK_HOST_DISCOVERY 1
#define TASK_OS_DETECTION 2
#define TASK_SYN_SCAN 3
#define TASK_NULL_SCAN 4
#define TASK_FIN_SCAN 5
#define TASK_XMAS_SCAN 6
#define TASK_ACK_SCAN 7
#define TASK_CONNECT_SCAN 8
#define TASK_WINDOW_SCAN 9
#define TASK_MAIMON_SCAN 10
#define TASK_UDP_SCAN 11

// PORT STATES
// ===========
#define PORT_OPEN 1
#define PORT_CLOSED 2
#define PORT_FILTERED 3
#define PORT_UNFILTERED 4
#define PORT_OPEN_FILTERED 5
#define PORT_CLOSED_FILTERED 6

// TYPEDEF
// =======
typedef struct option t_option;
typedef struct ifaddrs t_ifaddrs;
typedef struct sockaddr t_sockaddr;
typedef struct sockaddr_in t_sockaddr_in;
typedef struct sock_filter t_sock_filter;
typedef struct sock_fprog t_sock_fprog;
typedef struct in_addr t_in_addr;
typedef struct timeval t_timeval;
typedef struct iphdr t_iphdr;
typedef struct icmphdr t_icmphdr;
typedef struct udphdr t_udphdr;
typedef struct tcphdr t_tcphdr;
typedef struct hostent t_hostent;
typedef struct timeval t_timeval;
typedef struct winsize t_winsize;

// SIZES
// =====
#define T_OPTION_SIZE sizeof(t_option)
#define T_IFADDRS_SIZE sizeof(t_ifaddrs)
#define T_SOCKADDR_SIZE sizeof(t_sockaddr)
#define T_SOCKADDR_IN_SIZE sizeof(t_sockaddr_in)
#define T_SOCK_FILTER_SIZE sizeof(t_sock_filter)
#define T_SOCK_FPROG_SIZE sizeof(t_sock_fprog)
#define T_IN_ADDR_SIZE sizeof(t_in_addr)
#define T_TIMEVAL_SIZE sizeof(t_timeval)
#define T_IPHDR_SIZE sizeof(t_iphdr)
#define T_ICMPHDR_SIZE sizeof(t_icmphdr)
#define T_UDPHDR_SIZE sizeof(t_udphdr)
#define T_TCPHDR_SIZE sizeof(t_tcphdr)
#define T_HOSTENT_SIZE sizeof(t_hostent)
#define T_TIMEVAL_SIZE sizeof(t_timeval)
#define T_WINSIZE_SIZE sizeof(t_winsize)
#define PTHREAD_T_SIZE sizeof(pthread_t)

#define BYTE_SIZE sizeof(char)
#define SHORT_SIZE sizeof(short)
#define INT_SIZE sizeof(int)
#define LONG_SIZE sizeof(long)
#define SIZE_T_SIZE sizeof(size_t)
#define FLOAT_SIZE sizeof(float)
#define DOUBLE_SIZE sizeof(double)
#define PTR_SIZE sizeof(void*)

#define INT8_SIZE sizeof(int8_t)
#define INT16_SIZE sizeof(int16_t)
#define INT32_SIZE sizeof(int32_t)
#define INT64_SIZE sizeof(int64_t)

// OUTPUT
// ======
#define RST "\033[0m"
#define BOLD "\033[1m"
#define ITALIC "\033[3m"

#define GRAY "\033[1;30m"
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"

// BPF
// ===
#define LOAD_WORD (BPF_LD | BPF_W | BPF_ABS)
#define JUMP_EQUAL (BPF_JMP | BPF_JEQ | BPF_K)

#define OFF_SRC_IP 0x0C

#define RETURN (BPF_RET | BPF_K)
#define ACCEPT 0xFFFF
#define REJECT 0x0000

#endif
