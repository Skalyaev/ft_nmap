#include "../include/header.h"

extern t_nmap data;

static const char* usage() {

    return "\nNmap 0.1 (JeFéDuRézo edition)\n"\
           "\n"\
           "Usage: %s "GREEN"[OPTIONS]"RESET"\n"\
           "\n"\
           "TARGET SPECIFICATION:\n"\
           "\t"GREEN"-i --ip"RESET" IP1,HOST2...\t\tAdd targets\n"\
           "\t"GREEN"-f --file"RESET" FILE\t\t\tAdd targets from file\n"\
           "\n"\
           "HOST DISCOVERY:\n"\
           "\t"GREEN"-d --dns"RESET"\t\t\tEnable DNS resolution\n"\
           "\n"\
           "SCAN TECHNIQUES:\n"\
           "\t"GREEN"-s --scan"RESET" TYPE1,TYPE2,...\tAdd scan techniques\n"\
           "\t\t\t\t\t(SYN/NULL/FIN/XMAS/ACK\n"\
           "\t\t\t\t\tCONNECT/WINDOW/MAIMON/UDP)\n"\
           "\n"\
           "PORT SPECIFICATION:\n"\
           "\t"GREEN"-p --port"RESET" PORT1,PORT2,...\tAdd target ports\n"\
           "\n"\
           "OS DETECTION:\n"\
           "\t"GREEN"-o --os"RESET"\t\t\t\tEnable OS detection\n"\
           "\n"\
           "TIMING AND PERFORMANCE:\n"\
           "\t"GREEN"-t --speedup"RESET" THREADS\t\tNumber of threads to use\n"\
           "\n"\
           "FIREWALL/IDS EVASION:\n"\
           "\t"GREEN"-F --firewall"RESET"\t\t\tEnable firewall care\n"\
           "\t"GREEN"-I --ids"RESET"\t\t\tEnable IDS care\n"\
           "\n"\
           "MISSCELLANEOUS:\n"\
           "\t"GREEN"-h --help"RESET"\t\t\tPrint this message\n"\
           "\n"\
           "EXAMPLES:\n"\
           "\t%1$s -i 127.0.0.1 -p 80,443 -s CONNECT\n"\
           "\t%1$s -h exemple.com -o -s -t 250\n"\
           "\t%1$s -f targets.txt -d -p 1-1024\n\n";
}

static char** parse_arg(char* const arg) {

    char** const buffer = calloc(BUFFER_SIZE, PTR_SIZE);
    if(!buffer) {

        perror("calloc");
        return NULL;
    }
    char* token = strtok(arg, ",");
    bool failed = NO;
    for(ushort x = 0; token; x++) {

        if(x == BUFFER_SIZE - 1) {

            fprintf(stderr, "Error: too many arguments\n");
            failed = YES;
            break;
        }
        buffer[x] = strdup(token);
        token = strtok(NULL, ",");
    }
    if(failed) {

        for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);
        return NULL;
    }
    return buffer;
}

static char** parse_file(const char* const file) {

    FILE* const fd = fopen(file, "r");
    if(!fd) {

        perror("fopen");
        return NULL;
    }
    char** const buffer = calloc(BUFFER_SIZE, PTR_SIZE);
    if(!buffer) {

        perror("calloc");
        fclose(fd);
        return NULL;
    }
    char data[BUFFER_SIZE] = {0};
    ushort size;

    bool failed = NO;
    for(ushort x = 0; fgets(data, BUFFER_SIZE, fd); x++) {

        if(x == BUFFER_SIZE  - 1) {

            fprintf(stderr, "Error: too many arguments\n");
            failed = YES;
            break;
        }
        size = strlen(data);
        if(data[size - 1] != '\n') {

            fprintf(stderr, "Error: line too long\n");
            failed = YES;
            break;
        }
        buffer[x] = strndup(data, size - 1);
    }
    fclose(fd);
    if(failed) {

        for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);
        return NULL;
    }
    return buffer;
}

static ushort** parse_ports(char* const arg) {

    char** const buffer = parse_arg(arg);
    if(!buffer) return NULL;

    ushort size = 0;
    for(ushort x = 0; buffer[x]; x++) size++;

    ushort** const ports = calloc(BUFFER_SIZE, PTR_SIZE);
    if(!ports) {

        for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);

        perror("calloc");
        return NULL;
    }
    char* token;
    ushort start, end, idx;
    ushort offset = 0;

    bool failed = NO;
    for(ushort x = 0; x < size; x++) {

        if(!strchr(buffer[x], '-')) {

            ports[x] = malloc(SHORT_SIZE);
            if(!ports[x]) {

                perror("malloc");
                failed = YES;
                break;
            }
            *ports[x] = atoi(buffer[x]);
            if(!*ports[x]) {

                fprintf(stderr, "Error: invalid port '%s'\n", buffer[x]);
                failed = YES;
                break;
            }
            continue;
        }
        token = strtok(buffer[x], "-");
        if(!token) {

            fprintf(stderr, "Error: invalid port range\n");
            failed = YES;
            break;
        }
        start = atoi(token);
        token = strtok(NULL, "-");
        if(!token) {

            fprintf(stderr, "Error: invalid port range\n");
            failed = YES;
            break;
        }
        end = atoi(token);
        if(!start || !end || start > end) {

            fprintf(stderr, "Error: invalid port range\n");
            failed = YES;
            break;
        }
        for(ushort y = start; y <= end; y++) {

            idx = size + offset - 1;
            if(idx == BUFFER_SIZE - 1) {

                fprintf(stderr, "Error: too many ports\n");
                failed = YES;
                break;
            }
            ports[idx] = malloc(SHORT_SIZE);
            if(!ports[idx]) {

                perror("malloc");
                failed = YES;
                break;
            }
            *ports[idx] = y;
            offset++;
        }
        if(failed) break;
    }
    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    if(failed) {

        for(ushort x = 0; ports[x]; x++) free(ports[x]);
        free(ports);
        return NULL;
    }
    return ports;
}

static void default_ports() {

    const ushort ports[] = {

        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    };
    const size_t ports_size = sizeof(ports);

    memcpy(data.ports, ports, ports_size);
    data.opt.ports = ports_size / SHORT_SIZE;
}

static void default_scans() {

    data.opt.syn_scan = YES;
    data.opt.null_scan = YES;
    data.opt.fin_scan = YES;
    data.opt.xmas_scan = YES;
    data.opt.ack_scan = YES;
    data.opt.connect_scan = YES;
    data.opt.window_scan = YES;
    data.opt.maimon_scan = YES;
    data.opt.udp_scan = YES;
}

static byte new_hosts(const char opt, char* const optarg, char** const av) {

    char** const buffer = opt == 'f' ? parse_file(optarg) : parse_arg(optarg);
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

static byte new_scans(char* const optarg, char** const av) {

    char** const buffer = parse_arg(optarg);
    if(!buffer) return EXIT_FAILURE;

    bool failed = NO;
    for(ushort x = 0; buffer[x]; x++) {

        if(!strcmp(buffer[x], "SYN")) data.opt.syn_scan = YES;
        else if(!strcmp(buffer[x], "NULL")) data.opt.null_scan = YES;
        else if(!strcmp(buffer[x], "FIN")) data.opt.fin_scan = YES;
        else if(!strcmp(buffer[x], "XMAS")) data.opt.xmas_scan = YES;
        else if(!strcmp(buffer[x], "ACK")) data.opt.ack_scan = YES;
        else if(!strcmp(buffer[x], "CONNECT")) data.opt.connect_scan = YES;
        else if(!strcmp(buffer[x], "WINDOW")) data.opt.window_scan = YES;
        else if(!strcmp(buffer[x], "MAIMON")) data.opt.maimon_scan = YES;
        else if(!strcmp(buffer[x], "UDP")) data.opt.udp_scan = YES;
        else {
            fprintf(stderr, "%s: unknown scan type '%s'\n", av[0], buffer[x]);
            failed = YES;
            break;
        }
    }
    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);

    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

static byte new_ports(char* const optarg, char** const av) {

    ushort** const buffer = parse_ports(optarg);
    if(!buffer) return EXIT_FAILURE;

    ushort idx = data.opt.ports;
    bool failed = NO;
    bool duplicate;
    for(ushort x = 0; buffer[x]; x++) {

        if(idx >= MAX_PORTS) {

            fprintf(stderr, "%s: too many ports specified\n", av[0]);
            failed = YES;
            break;
        }
        duplicate = NO;
        for(ushort y = 0; data.ports[y]; y++) {

            if(*buffer[x] != data.ports[y]) continue;
            duplicate = YES;
            break;
        }
        if(duplicate) continue;
        data.ports[idx] = *buffer[x];
        idx++;
    }
    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);

    data.opt.ports = idx;
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

void getargs(const int ac, char** const av) {

    data.opt.threads = 1;
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
    const char* const optstring = "i:f:s:p:t:doenh";

    bool use_default_scans = YES;
    bool use_default_ports = YES;
    bool failed = NO;

    int idx = 0;
    int opt;
    while((opt = getopt_long(ac, av, optstring, options, &idx)) != -1) {

        switch(opt) {
        case 'i':
        case 'f':
            if(new_hosts(opt, optarg, av) == EXIT_FAILURE) failed = YES;
            break;
        case 'd':
            data.opt.resolve = YES;
            break;
        case 's':
            if(new_scans(optarg, av) == EXIT_FAILURE) failed = YES;
            use_default_scans = NO;
            break;
        case 'p':
            if(new_ports(optarg, av) == EXIT_FAILURE) failed = YES;
            use_default_ports = NO;
            break;
        case 'o':
            data.opt.os_detect = YES;
            break;
        case 't':
            data.opt.threads = atoi(optarg);
            if(data.opt.threads) break;

            failed = YES;
            fprintf(stderr, "%s: invalid number of threads '%s'\n",
                    av[0], optarg);
            break;
        case 'F':
            data.opt.firewall = YES;
            break;
        case 'I':
            data.opt.ids = YES;
            break;
        case 'h':
            printf(usage(), av[0]);

            for(ushort x = 0; data.hosts[x]; x++) free(data.hosts[x]);
            exit(EXIT_SUCCESS);
        default:
            failed = YES;
            fprintf(stderr, "try '%s -h' for more information\n", av[0]);
        }
        if(failed) break;
    }
    if(failed) {

        for(ushort x = 0; data.hosts[x]; x++) free(data.hosts[x]);
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
