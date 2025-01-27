#include "../include/header.h"

extern t_nmap data;

static const char* usage() {

    return "\nNmap 0.1 (JeFéDuRézo edition)\n"\
           "\n"\
           "Usage: %s "GREEN"[OPTIONS]"RESET"\n"\
           "\n"\
           "TARGET SPECIFICATION:\n"\
           "\t"GREEN"-i --ip"RESET" IP1,IP2,...\tAdd target IP addresses\n"\
           "\t"GREEN"-h --host"RESET" HOST1,HOST2,...\tAdd target hostnames\n"\
           "\t"GREEN"-f --file"RESET" FILE\t\tAdd target IP addresses from file\n"\
           "\n"\
           "HOST DISCOVERY:\n"\
           "\t"GREEN"-d --dns"RESET"\t\tResolve target IP addresses to hostnames\n"\
           "\n"\
           "SCAN TECHNIQUES:\n"\
           "\t"GREEN"-s --scan"RESET" TYPE1,TYPE2,...\tAdd scan techniques\n"\
           "\t\t\t(SYN/NULL/FIN/XMAS/ACK\n"\
           "\t\t\tCONNECT/WINDOW/MAIMON/UDP)\n"\
           "\n"\
           "PORT SPECIFICATION:\n"\
           "\t"GREEN"-p --port"RESET" PORT1,PORT2,...\tAdd target ports (range allowed)\n"\
           "\n"\
           "OS DETECTION:\n"\
           "\t"GREEN"-o --os"RESET"\t\tEnable OS detection\n"\
           "\n"\
           "TIMING AND PERFORMANCE:\n"\
           "\t"GREEN"-t --speedup"RESET" THREADS\tNumber of threads to use\n"\
           "\n"\
           "FIREWALL/IDS EVASION:\n"\
           "\t"GREEN"-e --escape"RESET"\tEnable firewall/IDS evasion\n"\
           "\t"GREEN"-n --ninja"RESET"\tSpoof source IP address\n"\
           "\n"\
           "MISSCELLANEOUS:\n"\
           "\t"GREEN"-h --help"RESET"\t\tPrint this help\n"\
           "\n"\
           "EXAMPLES:\n"\
           "\t%1$s -i 127.0.0.1 -p 80,443 -s CONNECT\n"\
           "\t%1$s -h exemple.com -o -s -t 250\n"\
           "\t%1$s -f targets.txt -d -p 1-1024\n"\
}

static void parse_arg(const char* const arg, char** const dst) {

    (void)arg;
    (void)dst;
    // WORK IN PROGRESS
}

static void default_ports() {

    const ushort ports[] = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    };
    memcpy(data.ports, ports, sizeof(ports));
}

void getargs(const int ac, char** const av) {

    data.opt.threads = 1;
    const t_option options[] = {

        {"ip", required_argument, 0, 'i'},
        {"host", required_argument, 0, 'h'},
        {"file", required_argument, 0, 'f'},
        {"dns", no_argument, 0, 'd'},
        {"scan", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"os", no_argument, 0, 'o'},
        {"speedup", required_argument, 0, 't'},
        {"escape", no_argument, 0, 'e'},
        {"ninja", no_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    const char* const optstring = "ch";

    int idx = 0;
    int opt;
    while((opt = getopt_long(ac, av, optstring, options, &idx)) != -1) {

        switch(opt) {
        // WORK IN PROGRESS
        case 'h':
            printf(usage(), av[0]);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
            exit(EXIT_FAILURE);
        }
    }
    if(!data.ports[0]) default_ports();
    if(data.hosts[0]) return;

    fprintf(stderr, "Error: no target specified.\n");
    fprintf(stderr, "try '%s -h' for more information.\n", av[0]);
}
