#include "../include/header.h"

t_nmap data = {0};

static void* worker() {

    while(YES) {

        tcp_probe(data.hosts[0], data.ports[0], TH_SYN);
        usleep(data.opt.sleep_time);
        // Try OS detection
        // Else Try port scanning
        // Else Try host discovery
        // Else break
    }
    return NULL;
}

int main(const int ac, char** const av) {

    srand(time(NULL));
    setlocale(LC_ALL, "");
    get_args(ac, av);

    data.opt.src_ip = get_host_ip();
    if(!data.opt.src_ip) return bye();

    for(uint8_t x = 0; x < data.opt.thread_count; x++) {

        if(pthread_create(&data.threads[x], NULL, worker, NULL) == 0)
            continue;

        perror("pthread_create");
        sigexit(errno);
    }
    signal(SIGINT, sigexit);
    signal(SIGQUIT, sigexit);
    signal(SIGTERM, sigexit);

    for(uint8_t x = 0; x < data.opt.thread_count; x++)
        pthread_join(data.threads[x], NULL);

    return bye();
}
