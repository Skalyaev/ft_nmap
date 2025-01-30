#include "../../include/header.h"

extern t_nmap data;

static int8_t switch_opt(const int opt,
                         char* const arg,
                         char** const av,
                         bool* const use_default_scans,
                         bool* const use_default_ports) {
    switch(opt) {
    case 'i':
    case 'f':
        if(new_hosts(opt, arg) == EXIT_FAILURE) return EXIT_FAILURE;
        break;
    case 'd':
        data.opt.flags |= RESOLVE;
        break;
    case 's':
        if(new_scans(arg) == EXIT_FAILURE) return EXIT_FAILURE;
        *use_default_scans = NO;
        break;
    case 'p':
        if(new_ports(arg) == EXIT_FAILURE) return EXIT_FAILURE;
        *use_default_ports = NO;
        break;
    case 'o':
        data.opt.flags |= OS_DETECT;
        break;
    case 't':
        data.opt.thread_count = atoi(arg);
        if(data.opt.thread_count && data.opt.thread_count <= MAX_THREADS) break;

        fprintf(stderr, "Error: invalid number of threads '%s'\n", arg);
        return EXIT_FAILURE;
    case 'F':
        data.opt.flags |= FIREWALL_CARE;
        data.opt.sleep_time = DEFAULT_SLEEP_TIME * 4;
        break;
    case 'I':
        data.opt.flags |= IDS_CARE;
        data.opt.sleep_time = DEFAULT_SLEEP_TIME * 4;
        break;
    case 'h':
        printf(usage(), av[0]);

        for(uint16_t x = 0; data.hosts[x]; x++) free(data.hosts[x]);
        exit(EXIT_SUCCESS);
    default:
        fprintf(stderr, "try '%s -h' for more information\n", av[0]);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

void get_args(const int ac, char** const av) {

    data.opt.sleep_time = DEFAULT_SLEEP_TIME;
    data.opt.thread_count = 1;
    const t_option options[] = {

        {"ip", required_argument, 0, 'i'},
        {"file", required_argument, 0, 'f'},
        {"dns", no_argument, 0, 'd'},
        {"scan", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"os", no_argument, 0, 'o'},
        {"speedup", required_argument, 0, 't'},
        {"firewall", no_argument, 0, 'F'},
        {"ids", no_argument, 0, 'I'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    const char* const optstring = "i:f:s:p:t:doFIh";

    bool use_default_scans = YES;
    bool use_default_ports = YES;
    bool failed = NO;

    int idx = 0;
    int opt;
    while((opt = getopt_long(ac, av, optstring, options, &idx)) != -1) {

        if(switch_opt(opt, optarg, av,
                      &use_default_scans,
                      &use_default_ports) == EXIT_SUCCESS) continue;
        failed = YES;
        break;
    }
    if(failed) {

        for(uint16_t x = 0; data.hosts[x]; x++) free(data.hosts[x]);
        exit(EXIT_FAILURE);
    }
    if(data.hosts[0]) {

        if(use_default_scans) default_scans();
        if(use_default_ports) default_ports();
        return;
    }
    fprintf(stderr, "%s: no target specified\n", av[0]);
    fprintf(stderr, "try '%s -h' for more information\n", av[0]);
    exit(EXIT_FAILURE);
}
