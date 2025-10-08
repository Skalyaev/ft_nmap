#include "../include/header.h"

t_nmap data = {0};

static void* worker() {

    t_task* task = NULL;
    while(YES) {

        task = get_next_task();
        if(!task) break;

        switch(task->type) {

        case TASK_HOST_DISCOVERY:
            host_discovery(task);
            break;

        case TASK_OS_DETECTION:
            os_detection(task);
            break;

        default:
            port_scan(task);
            break;
        }
        if(getcode()) break;
        usleep(data.opt.task_interval);
    }
    return NULL;
}

int main(const int ac, char** const av) {

    srand(time(NULL));
    setlocale(LC_ALL, "");

    if(parse_args(ac, av) == FAILURE) return bye();
    if(build_tasklist() == FAILURE) return bye();
    if(get_src_ip() == FAILURE) return bye();

    const uint8_t thread_count = data.opt.thread_count;

    data.code_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    data.results_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    data.output_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;

    if(pthread_create(&data.threads[thread_count],
                      NULL, logger, NULL) == -1) {

        error(strerror(errno));
        sigexit(errno);
    }
    for(uint8_t x = 0; x < thread_count; x++) {

        if(pthread_create(&data.threads[x], NULL, worker, NULL) == 0)
            continue;

        error(strerror(errno));
        sigexit(errno);
    }
    signal(SIGINT, sigexit);
    signal(SIGQUIT, sigexit);
    signal(SIGTERM, sigexit);

    for(uint8_t x = 0; x < thread_count; x++)
        pthread_join(data.threads[x], NULL);

    pthread_mutex_lock(&data.code_mutex);
    data.done = YES;
    pthread_mutex_unlock(&data.code_mutex);

    pthread_join(data.threads[thread_count], NULL);
    return bye();
}
