#include "../../include/header.h"

extern t_nmap data;

static void udp_hdr(t_udphdr* const hdr,
                    const uint16_t src_port,
                    const uint16_t dst_port) {

    hdr->uh_sport = htons(src_port);
    hdr->uh_dport = htons(dst_port);
    hdr->uh_ulen = htons(T_UDPHDR_SIZE);
}

static void udp_checksum(const t_iphdr* const iphdr,
                         t_udphdr* const udphdr) {

    t_pseudo_iphdr pseudo_iphdr = {0};
    pseudo_iphdr.protocol = IPPROTO_UDP;

    pseudo_iphdr.saddr = iphdr->saddr;
    pseudo_iphdr.daddr = iphdr->daddr;
    pseudo_iphdr.len = htons(T_UDPHDR_SIZE);

    uint8_t buffer[BUFFER_SIZE + 1] = {0};
    uint8_t size = 0;

    memcpy(buffer, &pseudo_iphdr, T_PSEUDO_IPHDR_SIZE);
    size += T_PSEUDO_IPHDR_SIZE;

    memcpy(buffer + size, udphdr, T_UDPHDR_SIZE);
    size += T_UDPHDR_SIZE;

    udphdr->uh_sum = checksum((uint16_t*)buffer, size);
}

int8_t udp_probe(const char* const dst_host,
                 const uint16_t dst_port,
                 uint8_t* const recv_buff) {

    static uint16_t idx = 0;
    if(++idx == 32768) idx = 0;

    const uint16_t src_port = 32768 + idx;

    t_socket udp_sock = new_socket(dst_host, dst_port, IPPROTO_UDP);
    if(udp_sock.fd == -1) return FAILURE;

    t_socket icmp_sock = new_socket(dst_host, 0, IPPROTO_ICMP);
    if(icmp_sock.fd == -1) {

        close(udp_sock.fd);
        return FAILURE;
    }
    uint8_t send_buff[BUFFER_SIZE + 1] = {0};

    const uint32_t src_ip = data.opt.src_ip;
    const uint32_t dst_ip = udp_sock.addr.sin_addr.s_addr;

    t_iphdr* iphdr = (t_iphdr*)send_buff;
    ip_hdr(iphdr, IPPROTO_UDP, src_ip, dst_ip);

    const uint8_t iphdr_size = iphdr->ihl << 2;
    const uint8_t headers_size = iphdr_size + T_UDPHDR_SIZE;

    t_udphdr* const udphdr = (t_udphdr*)(send_buff + iphdr_size);

    udp_hdr(udphdr, src_port, dst_port);
    udp_checksum(iphdr, udphdr);

    for(uint8_t attempt = 0; attempt < REQ_RETRIES; attempt++) {

        if(new_probe(&udp_sock, headers_size,
                     send_buff, recv_buff,
                     IPPROTO_UDP, src_port, dst_port) == FAILURE) break;
        if(*recv_buff) break;

        bool found = NO;
        while(YES) {

            if(recv(icmp_sock.fd, recv_buff, BUFFER_SIZE, 0) == -1) {

                if(errno == EAGAIN) break;
                setcode(errno);
                error(strerror(errno));
                break;
            }
            t_iphdr* const ipr = (t_iphdr*)recv_buff;
            if(ipr->protocol != IPPROTO_ICMP) continue;

            const uint8_t ihl = ipr->ihl << 2;
            t_icmphdr* const icmp = (t_icmphdr*)(recv_buff + ihl);
            if(icmp->type != ICMP_DEST_UNREACH) continue;

            uint8_t* const inner = recv_buff + ihl + T_ICMPHDR_SIZE;
            t_iphdr* const in_ip = (t_iphdr*)inner;

            const uint8_t in_ihl = in_ip->ihl << 2;
            if(in_ip->protocol != IPPROTO_UDP) continue;

            t_udphdr* const in_udp = (t_udphdr*)(inner + in_ihl);
            if(ntohs(in_udp->uh_sport) != src_port) continue;
            if(ntohs(in_udp->uh_dport) != dst_port) continue;

            found = YES;
            break;
        }
        if(found) break;
    }
    close(udp_sock.fd);
    close(icmp_sock.fd);
    return getcode() ? FAILURE : SUCCESS;
}
