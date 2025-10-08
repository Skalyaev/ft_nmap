#include "../include/header.h"

extern t_nmap data;

static int8_t new_task(t_task*** const ptr,
                       const uint8_t type,
                       const char* const host,
                       const uint16_t port) {

    t_task* const task = malloc(T_TASK_SIZE);
    if(!task) {

        data.code = errno;
        error(strerror(errno));
        return FAILURE;
    }
    memset(task, 0, T_TASK_SIZE);

    task->host = strdup(host);
    if(!task->host) {

        free(task);
        data.code = errno;
        error(strerror(errno));
        return FAILURE;
    }
    task->port = port;
    task->type = type;
    task->available = YES;
    task->next = NULL;

    **ptr = task;
    *ptr = &task->next;
    return SUCCESS;
}

static int8_t add_port_scan(t_task*** const ptr, const uint8_t type) {

    for(uint16_t x = 0; data.hosts[x]; x++) {
        for(uint16_t y = 0; data.ports[y]; y++) {

            if(new_task(ptr, type, data.hosts[x], data.ports[y]) == FAILURE)
                return FAILURE;
        }
    }
    return SUCCESS;
}

int8_t build_tasklist() {

    t_task** ptr = &data.tasklist;

    for(uint16_t x = 0; data.hosts[x]; x++) {

        if(new_task(&ptr, TASK_HOST_DISCOVERY, 
                    data.hosts[x], 0) == FAILURE) return FAILURE;
    }
    if(data.opt.flags & OS_DETECT) {

        for(uint16_t x = 0; data.hosts[x]; x++) {

            if(new_task(&ptr, TASK_OS_DETECTION,
                        data.hosts[x], 0) == FAILURE) return FAILURE;
        }
    }
    if(data.opt.flags & SYN_SCAN)
        if(add_port_scan(&ptr, TASK_SYN_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & NULL_SCAN)
        if(add_port_scan(&ptr, TASK_NULL_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & FIN_SCAN)
        if(add_port_scan(&ptr, TASK_FIN_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & XMAS_SCAN)
        if(add_port_scan(&ptr, TASK_XMAS_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & ACK_SCAN)
        if(add_port_scan(&ptr, TASK_ACK_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & CONNECT_SCAN)
        if(add_port_scan(&ptr, TASK_CONNECT_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & WINDOW_SCAN)
        if(add_port_scan(&ptr, TASK_WINDOW_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & MAIMON_SCAN)
        if(add_port_scan(&ptr, TASK_MAIMON_SCAN) == FAILURE)
            return FAILURE;

    if(data.opt.flags & UDP_SCAN)
        if(add_port_scan(&ptr, TASK_UDP_SCAN) == FAILURE)
            return FAILURE;

    return SUCCESS;
}

t_task* get_next_task() {

    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);

    t_task* task = data.tasklist;

    while(task && !task->available) task = task->next;
    if(task) task->available = NO;

    pthread_mutex_unlock(&mutex);
    return task;
}
