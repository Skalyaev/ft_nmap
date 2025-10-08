#include "../../include/header.h"

extern t_nmap data;

int8_t new_hosts(const char opt, char* const arg) {

    static uint16_t idx = 0;

    char** const buffer = opt == 'i' ? read_arg(arg) : read_file(arg);
    if(!buffer) return FAILURE;

    bool duplicate;

    for(uint16_t x = 0; buffer[x]; x++) {

        if(idx == MAX_HOSTS) {

            data.code = E2BIG;
            error(strerror(E2BIG));
            break;
        }
        duplicate = NO;

        for(uint16_t y = 0; data.hosts[y]; y++) {

            if(strcmp(buffer[x], data.hosts[y])) continue;
            duplicate = YES;
            break;
        }
        if(duplicate) continue;

        if(!valid_host(buffer[x])) {

            data.code = EINVAL;
            error(strerror(EINVAL));
            break;
        }
        data.hosts[idx] = strdup(buffer[x]);
        if(!data.hosts[idx]) {

            data.code = errno;
            error(strerror(errno));
            break;
        }
        idx++;
    }
    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);

    return data.code ? FAILURE : SUCCESS;
}
