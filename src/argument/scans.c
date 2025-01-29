#include "../../include/header.h"

extern t_nmap data;

void default_scans() {

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

byte new_scans(char* const optarg, char** const av) {

    char** const buffer = read_arg(optarg);
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
