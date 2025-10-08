#include "../../include/header.h"

void usage(const char* const name) {

    const char* const msg = "\n"\
        BOLD"Nmap "RST""ITALIC"(JeFéDuRézo edition)"RST"\n"\
        "\n"\
        BOLD"USAGE: "RST"%s "GREEN"[OPTION(S)]"RST"\n"\
        "\n"\
        BOLD"TARGET SPECIFICATION:"RST"\n"\
        "\t"GREEN"-i --ip"RST" IP1,HOST2\tTarget hosts\n"\
        "\t"GREEN"-f --file"RST" FILE\t\tTarget hosts from file\n"\
        "\t"GREEN"-p --ports"RST" PORTS\tTarget ports\n"\
        "\n"\
        BOLD"SCAN TECHNIQUES:"RST"\n"\
        "\t"GREEN"-s --scan"RST" TYPES\t\tScan techniques\n"\
        "\t\t\t\t(SYN/NULL/FIN/XMAS/ACK\n"\
        "\t\t\t\tCONNECT/WINDOW/MAIMON/UDP)\n"\
        ""\
        BOLD"OS DETECTION:"RST"\n"\
        "\t"GREEN"-o --os"RST"\t\t\tOS detection\n"\
        "\n"\
        BOLD"TIMING AND PERFORMANCE:"RST"\n"\
        "\t"GREEN"-t --speedup"RST" THREADS\tWorking threads (1-250)\n"\
        "\t"GREEN"-T --timing"RST" LEVEL\tTiming level (1-5)\n"\
        "\n"\
        BOLD"FIREWALL/IDS EVASION:"RST"\n"\
        "\t"GREEN"-F --fragment"RST"\t\tPacket fragmentation\n"\
        "\t"GREEN"-I --source-ip"RST"\t\tSource IP address\n"\
        "\n"\
        BOLD"MISCELLANEOUS:"RST"\n"\
        "\t"GREEN"-h --help"RST"\t\tHelp message\n"\
        "\n";
    printf(msg, name);
}
