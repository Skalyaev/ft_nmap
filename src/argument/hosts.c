#include "../../include/header.h"

extern t_nmap data;

byte new_hosts(const char opt, char* const optarg, char** const av) {

    char** const buffer = opt == 'f' ? read_file(optarg) : read_arg(optarg);
    if(!buffer) return EXIT_FAILURE;

    ushort idx = data.opt.hosts;
    bool failed = NO;
    bool duplicate;
    for(ushort x = 0; buffer[x]; x++) {

        if(idx >= MAX_HOSTS) {

            fprintf(stderr, "%s: too many hosts specified\n", av[0]);
            failed = YES;
            break;
        }
        duplicate = NO;
        for(ushort y = 0; data.hosts[y]; y++) {

            if(strcmp(buffer[x], data.hosts[y])) continue;
            duplicate = YES;
            break;
        }
        if(duplicate) continue;
        data.hosts[idx] = strdup(buffer[x]);
        idx++;
    }
    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);

    data.opt.hosts = idx;
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
