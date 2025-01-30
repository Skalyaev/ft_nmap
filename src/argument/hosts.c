#include "../../include/header.h"

extern t_nmap data;

int8_t new_hosts(const char opt, char* const arg) {

    static uint16_t idx = 0;

    char** const buffer = opt == 'f' ? read_file(arg) : read_arg(arg);
    if(!buffer) return EXIT_FAILURE;

    bool failed = NO;
    bool duplicate;
    for(uint16_t x = 0; buffer[x]; x++) {

        if(idx == MAX_HOSTS) {

            fprintf(stderr, "Error: too many hosts specified\n");
            failed = YES;
            break;
        }
        duplicate = NO;
        for(uint16_t y = 0; data.hosts[y]; y++) {

            if(strcmp(buffer[x], data.hosts[y])) continue;
            duplicate = YES;
            break;
        }
        if(duplicate) continue;

        data.hosts[idx] = strdup(buffer[x]);
        if(!data.hosts[idx]) {

            perror("strdup");
            failed = YES;
            break;
        }
        idx++;
    }
    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
