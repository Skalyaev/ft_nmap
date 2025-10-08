#include "../../include/header.h"

extern t_nmap data;

static int8_t fill_host(t_scan* const result, const char* const host) {

    t_in_addr addr = {0};
    if(inet_pton(AF_INET, host, &addr) == 1) {
 
        result->ip = strdup(host);
        return SUCCESS;
    }
    result->domain = strdup(host);
    if(!result->domain) {

        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    t_hostent* const hent = gethostbyname(host);
    if(!hent || hent->h_addrtype != AF_INET) {

        free(result->domain);
        setcode(EINVAL);
        error(strerror(EINVAL));
        return FAILURE;
    }
    result->ip = strdup(inet_ntoa(*(t_in_addr*)hent->h_addr));
    if(!result->ip) {

        free(result->domain);
        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

static void save_result(t_scan* const result) {

    pthread_mutex_lock(&data.results_mutex);

    t_scan** ptr = &data.results;
    t_scan* last = NULL;

    while(*ptr) {
 
        last = *ptr;
        ptr = &(*ptr)->next;
    }
    *ptr = malloc(T_SCAN_SIZE);
    if(!*ptr) {
 
        setcode(errno);
        error(strerror(errno));

        free(result->ip);
        if(result->domain) free(result->domain);

        pthread_mutex_unlock(&data.results_mutex);
        return;
    }
    memcpy(*ptr, result, T_SCAN_SIZE);

    (*ptr)->next = NULL;
    if(last) last->next = *ptr;

    pthread_mutex_unlock(&data.results_mutex);
}

void host_discovery(const t_task* const task) {

    t_scan result = {0};
    if(fill_host(&result, task->host) == FAILURE) return;

    uint8_t recv_buff[BUFFER_SIZE + 1] = {0};
    if(tcp_probe(result.ip, 80, TH_ACK, recv_buff) == FAILURE) {
            
        free(result.ip);
        if(result.domain) free(result.domain);
        return;
    }
    if(*recv_buff) result.up = YES;
    else {
 
        memset(recv_buff, 0, BUFFER_SIZE);
        if(icmp_probe(result.ip, recv_buff) == FAILURE) {
 
            free(result.ip);
            if(result.domain) free(result.domain);
            return;
        }
        if(*recv_buff) result.up = YES;
    }
    save_result(&result);
}
