#include "../../include/header.h"

extern t_nmap data;

static void icmp_hdr(t_icmphdr* const hdr,
                     const uint16_t id,
                     const uint16_t sequence) {

    hdr->type = ICMP_ECHO;
    hdr->un.echo.id = htons(id);
    hdr->un.echo.sequence = htons(sequence);
}

static void icmp_checksum(t_icmphdr* const icmphdr) {

    uint8_t buffer[BUFFER_SIZE + 1] = {0};
    memcpy(buffer, icmphdr, T_ICMPHDR_SIZE);

    icmphdr->checksum = checksum((uint16_t*)buffer, T_ICMPHDR_SIZE);
}

int8_t icmp_probe(const char* const dst_host,
                  uint8_t* const recv_buff) {

    static uint16_t id_counter = 0;
    static uint16_t seq_counter = 0;
    id_counter++;
    seq_counter++;

    t_socket sock = new_socket(dst_host, 0, IPPROTO_ICMP);
    if(sock.fd == -1) return FAILURE;

    uint8_t send_buff[BUFFER_SIZE + 1] = {0};

    const uint32_t src_ip = data.opt.src_ip;
    const uint32_t dst_ip = sock.addr.sin_addr.s_addr;

    t_iphdr* const iphdr = (t_iphdr*)send_buff;
    ip_hdr(iphdr, IPPROTO_ICMP, src_ip, dst_ip);

    const uint8_t iphdr_size = iphdr->ihl << 2;

    t_icmphdr* const icmphdr = (t_icmphdr*)(send_buff + iphdr_size);
    icmp_hdr(icmphdr, id_counter, seq_counter);
    icmp_checksum(icmphdr);

    const uint8_t headers_size = iphdr_size + T_ICMPHDR_SIZE;

    for(uint8_t x = 0; x < REQ_RETRIES; x++) {

        if(new_probe(&sock, headers_size,
                     send_buff, recv_buff,
                     IPPROTO_ICMP, 0, 0) == FAILURE) break;
        if(*recv_buff) break;
    }
    close(sock.fd);
    return getcode() ? FAILURE : SUCCESS;
}

