#ifndef STRUCT_H
#define STRUCT_H

typedef struct opt {
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
    bool escape;
    bool ninja;
} t_opt;

typedef struct nmap {
    t_opt opt;
    byte code;
    pthread_t* threads[MAX_THREADS];
    char* hosts[MAX_HOSTS];
    ushort ports[MAX_PORTS];
} t_nmap;

#define OPT_SIZE sizeof(t_opt)
#define NMAP_SIZE sizeof(t_nmap)
#define PTHREAD_T_SIZE sizeof(pthread_t)

#endif
