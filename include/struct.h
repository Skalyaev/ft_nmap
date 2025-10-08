#ifndef STRUCT_H
#define STRUCT_H

enum {
    SYN_SCAN = 1 << 0,
    NULL_SCAN = 1 << 1,
    FIN_SCAN = 1 << 2,
    XMAS_SCAN = 1 << 3,
    ACK_SCAN = 1 << 4,
    CONNECT_SCAN = 1 << 5,
    WINDOW_SCAN = 1 << 6,
    MAIMON_SCAN = 1 << 7,
    UDP_SCAN = 1 << 8,
    OS_DETECT = 1 << 9,
    PACKET_FRAGMENT = 1 << 10
};
typedef struct opt {
    uint16_t flags;
    uint32_t src_ip;
    uint8_t thread_count;
    uint32_t task_interval;
} t_opt;

typedef struct task {
    bool available;
    uint8_t type;
    char* host;
    uint16_t port;
    struct task* next;
} t_task;

typedef struct port_state {
    uint16_t port;
    uint8_t syn_scan_state;
    uint8_t null_scan_state;
    uint8_t fin_scan_state;
    uint8_t xmas_scan_state;
    uint8_t ack_scan_state;
    uint8_t connect_scan_state;
    uint8_t window_scan_state;
    uint8_t maimon_scan_state;
    uint8_t udp_scan_state;
    uint8_t conclusion;
    char* service;
} t_port_state;

typedef struct scan {
    char* domain;
    char* ip;
    char* os;
    bool up;
    t_port_state ports[MAX_PORTS + 1];
    struct scan* next;
} t_scan;

typedef struct nmap {
    t_opt opt;
    char* hosts[MAX_HOSTS + 1];
    uint16_t ports[MAX_PORTS + 1];
    pthread_t threads[MAX_THREADS + 2];
    t_task* tasklist;
    t_scan* results;
    int8_t code;
    bool done;
    pthread_mutex_t code_mutex;
    pthread_mutex_t results_mutex;
    pthread_mutex_t output_mutex;
} t_nmap;

typedef struct socket {
    int fd;
    t_sockaddr_in addr;
} t_socket;

typedef struct send {
    t_socket* sock;
    uint8_t* buffer;
    uint8_t headers_size;
} t_send;

typedef struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t len;
} t_pseudo_iphdr;

#define T_OPT_SIZE sizeof(t_opt)
#define T_TASK_SIZE sizeof(t_task)
#define T_PORT_STATE_SIZE sizeof(t_port_state)
#define T_SCAN_SIZE sizeof(t_scan)
#define T_NMAP_SIZE sizeof(t_nmap)
#define T_SOCKET_SIZE sizeof(t_socket)
#define T_SEND_SIZE sizeof(t_send)
#define T_PSEUDO_IPHDR_SIZE sizeof(t_pseudo_iphdr)

#endif
