#include "../../include/header.h"

const char* usage() {

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
