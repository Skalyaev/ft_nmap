#ifndef STRUCT_H
#define STRUCT_H

enum {
    RESOLVE = 1 << 0,
    SYN_SCAN = 1 << 1,
    NULL_SCAN = 1 << 2,
    FIN_SCAN = 1 << 3,
    XMAS_SCAN = 1 << 4,
    ACK_SCAN = 1 << 5,
    CONNECT_SCAN = 1 << 6,
    WINDOW_SCAN = 1 << 7,
    MAIMON_SCAN = 1 << 8,
    UDP_SCAN = 1 << 9,
    OS_DETECT = 1 << 10,
    FIREWALL_CARE = 1 << 11,
    IDS_CARE = 1 << 12
};
typedef struct opt {
    uint8_t thread_count;
    uint16_t flags;
    uint32_t src_ip;
    uint32_t sleep_time;
} t_opt;

typedef struct nmap {
    t_opt opt;
    int8_t code;
    char* hosts[MAX_HOSTS + 1];
    uint16_t ports[MAX_PORTS + 1];
    pthread_t threads[MAX_THREADS + 1];
} t_nmap;

#define OPT_SIZE sizeof(t_opt)
#define NMAP_SIZE sizeof(t_nmap)

typedef struct socket {
    int fd;
    t_sockaddr_in addr;
} t_socket;

typedef struct send {
    t_socket* sock;
    uint8_t* buffer;
    uint16_t size;
} t_send;

#define T_SOCKET_SIZE sizeof(t_socket)
#define T_SEND_SIZE sizeof(t_send)

typedef struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t len;
} t_pseudo_iphdr;

#define T_PSEUDO_IPHDR_SIZE sizeof(t_pseudo_iphdr)

#endif
