#include "../include/header.h"

t_nmap data = {0};

static void* worker() {

    while(YES) {

        usleep(100000);
        // Try OS detection
        // Else Try port scanning
        // Else Try host discovery
        // Else break
    }
    return NULL;
}

int main(const int ac, char** const av) {

    setlocale(LC_ALL, "");
    getargs(ac, av);
    tmp_print();

    const size_t size = data.opt.threads * PTHREAD_T_SIZE;
    void* buffer = malloc(size);
    if(!buffer) {

        data.code = errno;
        perror("calloc");
        return bye();
    }
    memset(data.threads, 0, size);

    for(ubyte x = 0; x < data.opt.threads; x++)
        data.threads[x] = buffer + (x * PTHREAD_T_SIZE);

    if(data.opt.escape && setup_escape() != EXIT_SUCCESS)
        return bye();

    for(ubyte x = 0; x < data.opt.threads; x++) {

        if(pthread_create(data.threads[x], NULL, worker, NULL) == 0)
            continue;

        data.code = errno;
        perror("pthread_create");
        sigexit(data.code);
    }
    signal(SIGINT, sigexit);
    signal(SIGQUIT, sigexit);
    signal(SIGTERM, sigexit);

    for(ubyte x = 0; x < data.opt.threads; x++)
        pthread_join(*data.threads[x], NULL);

    return bye();
}
