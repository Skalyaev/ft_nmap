#include "../../include/header.h"

extern t_nmap data;

void intro() {

    printf("\n");
    printf(GRAY""BOLD"#=========#"RST"\n");
    printf(GRAY""BOLD"# SUMMARY #"RST"\n");
    printf(GRAY""BOLD"#=========#"RST"\n\n");

    printf("Source IP\t\t");
    printf(BOLD"%s"RST"\n", inet_ntoa(*(t_in_addr*)&data.opt.src_ip));

    printf("Threads\t\t\t");
    printf(BOLD"%u"RST"\n", data.opt.thread_count);

    printf("Task Interval\t\t");
    printf(BOLD"%u ms"RST"\n", data.opt.task_interval / 1000);

    printf("Target hosts\t\t");
    for(uint16_t x = 0; data.hosts[x]; x++) {

        if(x && !(x % 2)) printf("\n\t\t\t");
        printf(BOLD"%s "RST, data.hosts[x]);
    }
    printf("\n");

    uint16_t port_count = 0;
    for(uint16_t x = 0; data.ports[x]; x++) port_count++;

    printf("Target port count\t");
    printf(BOLD"%u"RST"\n", port_count);

    const char* const scan_types_str[] = {

        "SYN", "NULL", "FIN", "XMAS", "ACK",
        "CONNECT", "WINDOW", "MAIMON", "UDP"
    };
    const uint16_t scan_types_flag[] = {

        SYN_SCAN, NULL_SCAN, FIN_SCAN, XMAS_SCAN, ACK_SCAN,
        CONNECT_SCAN, WINDOW_SCAN, MAIMON_SCAN, UDP_SCAN
    };
    const uint8_t scan_type_count = sizeof(scan_types_str) / PTR_SIZE;

    printf("Scan performed\t\t");
    for(uint8_t x = 0; x < scan_type_count; x++) {

        if(!(data.opt.flags & scan_types_flag[x])) continue;

        if(x && !(x % 3)) printf("\n\t\t\t");
        printf(BOLD"%s "RST, scan_types_str[x]);
    }
    printf("\n");

    printf("OS Detection\t\t");
    if(data.opt.flags & OS_DETECT) printf(BOLD"ON"RST"\n");
    else printf(BOLD"OFF"RST"\n");

    printf("Packet Fragmentation\t");
    if(data.opt.flags & PACKET_FRAGMENT) printf(BOLD"ON"RST"\n");
    else printf(BOLD"OFF"RST"\n");
}
