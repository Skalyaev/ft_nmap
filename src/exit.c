#include "../include/header.h"

extern t_nmap data;

void setcode(const int8_t code) {

    pthread_mutex_lock(&data.code_mutex);

    if(!data.code) data.code = code;
    pthread_mutex_unlock(&data.code_mutex);
}

int8_t getcode() {

    pthread_mutex_lock(&data.code_mutex);

    const int8_t code = data.code;
    pthread_mutex_unlock(&data.code_mutex);
    return code;
}

int8_t bye() {

    t_task* tmp_task = NULL;
    for(t_task* task = data.tasklist; task;) {

        tmp_task = task;
        task = task->next;

        free(tmp_task->host);
        free(tmp_task);
    }
    t_scan* tmp_result = NULL;
    for(t_scan* result = data.results; result;) {

        tmp_result = result;
        result = result->next;

        if(tmp_result->os) free(tmp_result->os);
        if(tmp_result->domain) free(tmp_result->domain);

        free(tmp_result->ip);
        free(tmp_result);
    }
    for(uint16_t x = 0; data.hosts[x]; x++) free(data.hosts[x]);
    return data.code;
}

void sigexit(const int sig) {

    static bool exiting = NO;

    if(exiting) return;
    else exiting = YES;

    const uint8_t thread_count = data.opt.thread_count;

    for(uint8_t x = 0; x < thread_count; x++) {

        if(!data.threads[x]) break;
        pthread_cancel(data.threads[x]);
    }
    for(uint8_t x = 0; x < thread_count; x++) {

        if(!data.threads[x]) break;
        pthread_join(data.threads[x], NULL);
    }
    if(data.threads[thread_count]) {

        pthread_cancel(data.threads[thread_count]);
        pthread_join(data.threads[thread_count], NULL);
    }
    data.code = sig;
    printf("\n\n");
    exit(bye());
}
