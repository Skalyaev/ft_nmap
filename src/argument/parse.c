#include "../../include/header.h"

extern t_nmap data;

static int8_t optswitch(const int opt,
                        char* const optarg,
                        char** const av,
                        bool* const use_default_scans,
                        bool* const use_default_ports) {
    switch(opt) {

    case 'i':
    case 'f':
        if(new_hosts(opt, optarg) == FAILURE) return FAILURE;
        break;

    case 'p':
        if(new_ports(optarg) == FAILURE) return FAILURE;
        *use_default_ports = NO;
        break;

    case 's':
        if(new_scans(optarg) == FAILURE) return FAILURE;
        *use_default_scans = NO;
        break;

    case 'o':
        data.opt.flags |= OS_DETECT;
        break;

    case 't':
        data.opt.thread_count = atoi(optarg);
        if(data.opt.thread_count && data.opt.thread_count <= MAX_THREADS)
                break;

        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;

    case 'F':
        data.opt.flags |= PACKET_FRAGMENT;
        break;

    case 'I':
        data.opt.src_ip = inet_addr(optarg);
        if(data.opt.src_ip != INADDR_NONE) break;

        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;

    case 'T':
        const uint32_t timing = atoi(optarg);
        if(!timing || timing > 5) {

            data.code = EINVAL;
            error(strerror(EINVAL));
            return FAILURE;
        }
        if(timing == 1) data.opt.task_interval = REQ_TASK_INTERVAL * 5;
        else if(timing == 2) data.opt.task_interval = REQ_TASK_INTERVAL * 2;
        else if(timing == 3) data.opt.task_interval = REQ_TASK_INTERVAL;
        else if(timing == 4) data.opt.task_interval = REQ_TASK_INTERVAL / 2;
        else if(timing == 5) data.opt.task_interval = REQ_TASK_INTERVAL / 5;
        break;

    case 'h':
        usage(av[0]);
        data.code = SUCCESS;
        return FAILURE;

    default:
        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;
    }
    return SUCCESS;
}

int8_t parse_args(const int ac, char** const av) {

    if(ac == 1) {

        usage(av[0]);
        data.code = EINVAL;
        return FAILURE;
    }
    data.opt.thread_count = 1;
    data.opt.task_interval = REQ_TASK_INTERVAL;

    bool use_default_scans = YES;
    bool use_default_ports = YES;

    const t_option opts[] = {

        {"ip", required_argument, 0, 'i'},
        {"file", required_argument, 0, 'f'},
        {"ports", required_argument, 0, 'p'},
        {"scan", required_argument, 0, 's'},
        {"os", no_argument, 0, 'o'},
        {"speedup", required_argument, 0, 't'},
        {"fragment", no_argument, 0, 'F'},
        {"source-ip", required_argument, 0, 'I'},
        {"timing", required_argument, 0, 'T'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    const char* const optstring = "i:f:p:s:t:I:T:oFh";
    extern char* optarg;
    extern int optind, opterr;
    opterr = 0;

    int opt = 0;
    int idx = 0;
    while(YES) {

        opt = getopt_long(ac, av, optstring, opts, &idx);
        if(opt == -1) break;

        if(optswitch(opt, optarg, av,
                     &use_default_scans,
                     &use_default_ports) == FAILURE) return FAILURE;
    }
    if(!data.hosts[0] || ac != optind) {

        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;
    }
    if(use_default_scans) default_scans();
    if(use_default_ports) default_ports();

    return SUCCESS;
}
