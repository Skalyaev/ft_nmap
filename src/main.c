#include "../include/header.h"

t_nmap data = {0};

static void* worker() {

    while(YES) {

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
    for(ubyte x = 0; x < data.opt.threads; x++) {

        data.thread[x] = malloc(PTHREAD_T_SIZE);
        if(!data.thread[x]) {

            data.code = errno;
            perror("malloc");
            return bye();
        }
        memset(data.thread[x], 0, PTHREAD_T_SIZE);
    }
    signal(SIGINT, sigexit);
    signal(SIGQUIT, sigexit);
    signal(SIGTERM, sigexit);

    if(data.opt.escape && setup_escape() != EXIT_SUCCESS)
        return bye();

    for(ubyte x = 0; x < data.opt.threads; x++) {

        if(pthread_create(&data.threads[x], NULL, worker, NULL) == 0)
            continue;

        data.code = errno;
        perror("pthread_create");
        sigexit(data.code);
    }
    for(ubyte x = 0; x < data.opt.threads; x++)
        pthread_join(data.threads[x], NULL);

    return bye();
}
