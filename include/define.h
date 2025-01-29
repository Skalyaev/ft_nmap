#ifndef DEFINE_H
#define DEFINE_H

#define MAX_THREADS 250
#define MAX_HOSTS 512
#define MAX_PORTS 1024

#define BUFFER_SIZE 1024
#define FRAGMENT_SIZE 8
#define TCP_WINDOW 5840

#define MIN_DATA_SIZE 4
#define MAX_DATA_SIZE 42
#define RANGE_DATA_SIZE (MAX_DATA_SIZE - MIN_DATA_SIZE + 1)

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define YES 1
#define NO 0

typedef char byte;
typedef unsigned char ubyte;
typedef unsigned char bool;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef struct option t_option;
typedef struct ifaddrs t_ifaddrs;
typedef struct sockaddr_in t_sockaddr_in;
typedef struct iphdr t_iphdr;
typedef struct tcphdr t_tcphdr;
typedef struct udphdr t_udphdr;
typedef struct icmphdr t_icmphdr;

#define BYTE_SIZE sizeof(byte)
#define SHORT_SIZE sizeof(short)
#define INT_SIZE sizeof(int)
#define LONG_SIZE sizeof(long)
#define SIZE_T_SIZE sizeof(size_t)
#define FLOAT_SIZE sizeof(float)
#define DOUBLE_SIZE sizeof(double)
#define PTR_SIZE sizeof(void*)

#define T_OPTION_SIZE sizeof(t_option)
#define T_SOCKADDR_IN_SIZE sizeof(t_sockaddr_in)
#define T_IPHDR_SIZE sizeof(t_iphdr)
#define T_TCPHDR_SIZE sizeof(t_tcphdr)
#define T_UDPHDR_SIZE sizeof(t_udphdr)
#define T_ICMPHDR_SIZE sizeof(t_icmphdr)

#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"
#define BLUE "\033[0;34m"
#define MAGENTA "\033[0;35m"
#define CYAN "\033[0;36m"
#define WHITE "\033[0;37m"
#define RESET "\033[0m"

#endif
