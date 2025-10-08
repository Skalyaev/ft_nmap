#include "../../include/header.h"

extern t_nmap data;

void error(const char* const msg) {

    pthread_mutex_lock(&data.output_mutex);

    fprintf(stderr, "\n"RED""BOLD"ERROR: "RST"%s\n\n", msg);
    pthread_mutex_unlock(&data.output_mutex);
}

void* logger() {

    t_timeval start = {0};
    gettimeofday(&start, NULL);

    t_timeval now = {0};
    t_timeval diff = {0};

    uint32_t m, s, ms;
    bool done = NO;

    pthread_mutex_lock(&data.output_mutex);
    intro();
    while(YES) {

        pthread_mutex_lock(&data.code_mutex);
        if(data.done || data.code) done = YES;
        pthread_mutex_unlock(&data.code_mutex);

        gettimeofday(&now, NULL);
        timersub(&now, &start, &diff);

        m = diff.tv_sec / 60;
        s = diff.tv_sec % 60;
        ms = diff.tv_usec / 10000;

        printf("\r\033[KDuration\t\t"BOLD"%02u:%02u:%02u"RST, m, s, ms);
        fflush(stdout);

        if(done) break;
        usleep(80000);
    }
    printf("\n");
    pthread_mutex_unlock(&data.output_mutex);

    if(!data.code) outro();
    return NULL;
}
