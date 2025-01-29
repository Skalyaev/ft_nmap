#include "../include/header.h"

extern t_nmap data;

void tcp_hdr(t_tcphdr* const hdr, const char** const flags,
             const ushort src_port, const ushort dport) {

    hdr->th_src_port = htons(src_port);
    hdr->th_dport = htons(dport);
    hdr->th_win = htons(TCP_WINDOW);

    for(ubyte x = 0; flags[x]; x++) {

        if(!strcmp(flags[x], "SYN")) hdr->th_flags |= TH_SYN;
        else if(!strcmp(flags[x], "FIN")) hdr->th_flags |= TH_FIN;
        else if(!strcmp(flags[x], "ACK")) hdr->th_flags |= TH_ACK;
        else if(!strcmp(flags[x], "RST")) hdr->th_flags |= TH_RST;
        else if(!strcmp(flags[x], "URG")) hdr->th_flags |= TH_URG;
        else if(!strcmp(flags[x], "PSH")) hdr->th_flags |= TH_PUSH;
    }
    hdr->th_seq = rand();
    //hdr->ack_seq = 0;
}

byte tcp_probe(const char* const dst_host, const ushort dst_port,
               const char** const flags) {

    static const ushort hdr_size = T_IPHDR_SIZE + T_TCPHDR_SIZE;
    static const ushort src_ports[] = {
        32768, 49152, 65535, 20, 80, 88, 139, 389, 443, 3389
    };
    static const ubyte src_ports_size = sizeof(src_ports) / SHORT_SIZE;
    static ubyte src_port_idx = 0;

    t_socket const sock = sock_raw(dst_host, dst_port, IPPROTO_TCP);
    if(!sock) return EXIT_FAILURE;

    ushort size = hdr_size;
    ubyte data_size = 0;

    ushort fragment_size = size;
    ubyte fragment_count = 1;

    if(data.opt.firewall || data.opt.ids) {

        data_size += MIN_DATA_SIZE + (rand() % RANGE_DATA_SIZE);
        size = hdr_size + data_size + 1;

        fragment_size = FRAGMENT_SIZE;
        fragment_count = size / FRAGMENT_SIZE;
    }
    byte payload[size];
    memset(payload, 0, size);

    t_iphdr* const iphdr = (t_iphdr*)payload;
    t_tcphdr* const tcphdr = (t_tcphdr*)(payload + T_IPHDR_SIZE);

    const uint32_t daddr = sock.addr.sin_addr.s_addr;
    ip_hdr(iphdr, IPPROTO_TCP, data.self.addr, daddr);
    // TODO: if ids -> decoys

    const ubyte idx = src_port_idx % src_ports_size;
    tcp_hdr(tcphdr, flags, src_ports[idx], dst_port);
    // TODO: if firewall -> try different ports

    byte* const data = payload + T_IPHDR_SIZE + T_TCPHDR_SIZE;
    for(ubyte x = 0; x < data_size; x++) data[x] = rand() % CHAR_MAX;

    bool failed = NO;
    for(ubyte x = 0; x < fragment_count && !failed; x++)
        if(send_tcp(sock, payload + (x * fragment_size),
                    fragment_size) == EXIT_FAILURE) failed = YES;
    close(sock.fd);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
