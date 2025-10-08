#include "../../include/header.h"

int8_t udp_scan(const char* const dst_host,
                const uint16_t dst_port) {

    uint8_t recv_buff[BUFFER_SIZE + 1] = {0};

    if(udp_probe(dst_host, dst_port, recv_buff) == FAILURE)
        return FAILURE;

    if(!*recv_buff) return PORT_OPEN_FILTERED;

    t_iphdr* const iphdr = (t_iphdr*)recv_buff;
    const uint8_t iphdr_size = iphdr->ihl << 2;

    if(iphdr->protocol == IPPROTO_ICMP) {

        t_icmphdr* const icmphdr = (t_icmphdr*)(recv_buff + iphdr_size);
        if(icmphdr->type != ICMP_DEST_UNREACH) return PORT_OPEN_FILTERED;

        if(icmphdr->code == ICMP_PORT_UNREACH) return PORT_CLOSED;
        return PORT_FILTERED;
    }
    return iphdr->protocol == IPPROTO_UDP ? PORT_OPEN : PORT_OPEN_FILTERED;
}
