#include "../../include/header.h"

extern t_nmap data;

static t_port_state get_port_state(const char* const host,
                                   const uint16_t port,
                                   const uint8_t task_type) {
    t_port_state state = {0};
    switch(task_type) {

    case TASK_SYN_SCAN:
        state.syn_scan_state = syn_scan(host, port);
        break;

    case TASK_NULL_SCAN:
        state.null_scan_state = null_scan(host, port);
        break;

    case TASK_FIN_SCAN:
        state.fin_scan_state = fin_scan(host, port);
        break;

    case TASK_XMAS_SCAN:
        state.xmas_scan_state = xmas_scan(host, port);
        break;

    case TASK_ACK_SCAN:
        state.ack_scan_state = ack_scan(host, port);
        break;

    case TASK_CONNECT_SCAN:
        state.connect_scan_state = connect_scan(host, port);
        break;

    case TASK_WINDOW_SCAN:
        state.window_scan_state = window_scan(host, port);
        break;

    case TASK_MAIMON_SCAN:
        state.maimon_scan_state = maimon_scan(host, port);
        break;

    case TASK_UDP_SCAN:
        state.udp_scan_state = udp_scan(host, port);
        break;
    }
    if(!getcode()) state.port = port;
    return state;
}

static void update_port_state(const t_port_state* const src,
                              t_port_state* const dst) {

    if(src->syn_scan_state) dst->syn_scan_state = src->syn_scan_state;
    if(src->null_scan_state) dst->null_scan_state = src->null_scan_state;
    if(src->fin_scan_state) dst->fin_scan_state = src->fin_scan_state;
    if(src->xmas_scan_state) dst->xmas_scan_state = src->xmas_scan_state;
    if(src->ack_scan_state) dst->ack_scan_state = src->ack_scan_state;
    if(src->connect_scan_state) dst->connect_scan_state = src->connect_scan_state;
    if(src->window_scan_state) dst->window_scan_state = src->window_scan_state;
    if(src->maimon_scan_state) dst->maimon_scan_state = src->maimon_scan_state;
    if(src->udp_scan_state) dst->udp_scan_state = src->udp_scan_state;
}

void port_scan(const t_task* const task) {

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
        usleep(100000);
    }
    if(!up) return;

    t_port_state port_state = get_port_state(ip, task->port, task->type);
    if(!port_state.port) return;

    pthread_mutex_lock(&data.results_mutex);
    uint16_t x = 0;
    while(x < MAX_PORTS) {

        if(!result->ports[x].port) break;
        if(result->ports[x].port == port_state.port) break;
        x++;
    }
    if(result->ports[x].port) update_port_state(&port_state, &result->ports[x]);
    else memcpy(&result->ports[x], &port_state, T_PORT_STATE_SIZE);

    pthread_mutex_unlock(&data.results_mutex);
}
