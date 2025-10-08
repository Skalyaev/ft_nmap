#include "../../include/header.h"

int8_t null_scan(const char* const dst_host,
                 const uint16_t dst_port) {

    static const uint8_t flags = 0;
    uint8_t recv_buff[BUFFER_SIZE + 1] = {0};

    if(tcp_probe(dst_host, dst_port, flags, recv_buff) == FAILURE)
        return FAILURE;

    if(!*recv_buff) return PORT_OPEN_FILTERED;

    t_iphdr* const iphdr = (t_iphdr*)recv_buff;
    const uint8_t iphdr_size = iphdr->ihl << 2;

    if(iphdr->protocol == IPPROTO_ICMP) {

        t_icmphdr* const icmphdr = (t_icmphdr*)(recv_buff + iphdr_size);
        if(icmphdr->type == ICMP_DEST_UNREACH) return PORT_FILTERED;
    }
    else if(iphdr->protocol == IPPROTO_TCP) {

        t_tcphdr* const tcphdr = (t_tcphdr*)(recv_buff + iphdr_size);
        if(tcphdr->th_flags & TH_RST) return PORT_CLOSED;
    }
    return PORT_OPEN_FILTERED;
}
