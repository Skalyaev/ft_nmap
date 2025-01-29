#ifndef STRUCT_H
#define STRUCT_H

typedef struct opt {
    ushort hosts;
    ushort ports;
    ubyte threads;
    bool resolve;
    bool syn_scan;
    bool null_scan;
    bool fin_scan;
    bool xmas_scan;
    bool ack_scan;
    bool connect_scan;
    bool window_scan;
    bool maimon_scan;
    bool udp_scan;
    bool os_detect;
    bool firewall;
    bool ids;
} t_opt;

typedef struct self {
    uint32_t addr;
} t_self;

typedef struct socket {
    int fd;
    t_sockaddr_in addr;
} t_socket;

typedef struct nmap {
    t_opt opt;
    byte code;
    t_self self;
    pthread_t threads[MAX_THREADS];
    char* hosts[MAX_HOSTS];
    ushort ports[MAX_PORTS];
} t_nmap;

#define OPT_SIZE sizeof(t_opt)
#define SELF_SIZE sizeof(t_self)
#define T_SOCK_SIZE sizeof(t_socket)
#define NMAP_SIZE sizeof(t_nmap)
#define PTHREAD_T_SIZE sizeof(pthread_t)

#endif
