#include "../../include/header.h"

extern t_nmap data;

static void conclusion(const uint8_t ttl,
                       const uint16_t win,
                       t_scan* const result) {

    const char* os = NULL;

    if(ttl >= 200) os = "Network device";
    else if(ttl >= 100) os = "Windows";
    else if(ttl >= 60) {

        if(win == 5840 || win == 29200 || win == 64240) os = "Linux/Unix";
        else os = "Unix-like";
    }
    else os = "Unknown";

    pthread_mutex_lock(&data.results_mutex);
    result->os = strdup(os);

    if(!result->os) {

        setcode(errno);
        error(strerror(errno));
    }
    pthread_mutex_unlock(&data.results_mutex);
}

void os_detection(const t_task* const task) {

    t_scan* result = NULL;
    char* ip = NULL;
    bool up = NO;

    while(!result) {

        pthread_mutex_lock(&data.results_mutex);
        for(t_scan* ptr = data.results; ptr; ptr = ptr->next) {

            if(ptr->domain && !strcmp(ptr->domain, task->host)) result = ptr;
            else if(!strcmp(ptr->ip, task->host)) result = ptr;

            if(!result) continue;
            ip = ptr->ip;
            up = ptr->up;
            break;
        }
        pthread_mutex_unlock(&data.results_mutex);
        if(!result) usleep(100000);
    }
    if(!up) return;

    uint8_t recv_buff[BUFFER_SIZE + 1] = {0};
    uint8_t ttl = 0;
    uint16_t win = 0;

    if(tcp_probe(ip, 80, TH_SYN, recv_buff) == SUCCESS && *recv_buff) {

        t_iphdr* const iphdr = (t_iphdr*)recv_buff;
        ttl = iphdr->ttl;

        const uint8_t ihl = iphdr->ihl << 2;
        if(iphdr->protocol == IPPROTO_TCP) {

            t_tcphdr* const tcphdr = (t_tcphdr*)(recv_buff + ihl);
            win = ntohs(tcphdr->th_win);
        }
    } else {
        memset(recv_buff, 0, BUFFER_SIZE + 1);

        if(icmp_probe(ip, recv_buff) != SUCCESS || !*recv_buff) return;

        t_iphdr* const iphdr = (t_iphdr*)recv_buff;
        ttl = iphdr->ttl;
    }
    conclusion(ttl, win, result);
}
