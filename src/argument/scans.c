#include "../../include/header.h"

extern t_nmap data;

void default_scans() {

    data.opt.flags |= SYN_SCAN;
    data.opt.flags |= NULL_SCAN;
    data.opt.flags |= FIN_SCAN;
    data.opt.flags |= XMAS_SCAN;
    data.opt.flags |= ACK_SCAN;
    data.opt.flags |= CONNECT_SCAN;
    data.opt.flags |= WINDOW_SCAN;
    data.opt.flags |= MAIMON_SCAN;
    data.opt.flags |= UDP_SCAN;
}

int8_t new_scans(char* const arg) {

    char** const buffer = read_arg(arg);
    if(!buffer) return EXIT_FAILURE;

    bool failed = NO;
    for(uint16_t x = 0; buffer[x]; x++) {

        if(!strcmp(buffer[x], "SYN")) data.opt.flags |= SYN_SCAN;
        else if(!strcmp(buffer[x], "NULL")) data.opt.flags |= NULL_SCAN;
        else if(!strcmp(buffer[x], "FIN")) data.opt.flags |= FIN_SCAN;
        else if(!strcmp(buffer[x], "XMAS")) data.opt.flags |= XMAS_SCAN;
        else if(!strcmp(buffer[x], "ACK")) data.opt.flags |= ACK_SCAN;
        else if(!strcmp(buffer[x], "CONNECT")) data.opt.flags |= CONNECT_SCAN;
        else if(!strcmp(buffer[x], "WINDOW")) data.opt.flags |= WINDOW_SCAN;
        else if(!strcmp(buffer[x], "MAIMON")) data.opt.flags |= MAIMON_SCAN;
        else if(!strcmp(buffer[x], "UDP")) data.opt.flags |= UDP_SCAN;
        else {
            fprintf(stderr, "Error: unknown scan type '%s'\n", buffer[x]);
            failed = YES;
            break;
        }
    }
    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
