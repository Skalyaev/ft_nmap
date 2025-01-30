#include "../include/header.h"

extern t_nmap data;

int8_t bye() {

    for(uint16_t x = 0; data.hosts[x]; x++) free(data.hosts[x]);
    return data.code;
}

void sigexit(const int sig) {

    static bool exiting = NO;
    if(exiting) return;
    else exiting = YES;

    for(uint8_t x = 0; x < data.opt.thread_count; x++) {

        if(!data.threads[x]) break;
        pthread_cancel(data.threads[x]);
    }
    for(uint8_t x = 0; x < data.opt.thread_count; x++) {

        if(!data.threads[x]) break;
        pthread_join(data.threads[x], NULL);
    }
    data.code = sig;
    exit(bye());
}
