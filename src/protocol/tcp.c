#include "../../include/header.h"

extern t_nmap data;

void tcp_hdr(t_tcphdr* const hdr, const char** const flags,
             const ushort src_port, const ushort dport) {

    hdr->th_sport = htons(src_port);
    hdr->th_dport = htons(dport);
    hdr->th_win = htons(5840);

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

static void tcp_checksum(t_iphdr* const iphdr, t_tcphdr* const tcphdr,
                         const byte* const body, const ubyte body_size) {

    t_pseudo_iphdr pseudo = {0};
    pseudo.saddr = iphdr->saddr;
    pseudo.daddr = iphdr->daddr;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.len = htons(T_TCPHDR_SIZE + body_size);

    byte buffer[BUFFER_SIZE] = {0};
    memcpy(buffer, &pseudo, T_PSEUDO_IPHDR_SIZE);
    memcpy(buffer + T_PSEUDO_IPHDR_SIZE, tcphdr, T_TCPHDR_SIZE);
    memcpy(buffer + T_PSEUDO_IPHDR_SIZE + T_TCPHDR_SIZE, body, body_size);

    const ushort size = T_PSEUDO_IPHDR_SIZE + T_TCPHDR_SIZE + body_size;
    tcphdr->th_sum = checksum((ushort*)buffer, size);
}

static void print_tcp_response(const byte* const buffer) {

    const t_iphdr* const iphdr = (t_iphdr*)buffer;
    const t_tcphdr* const tcphdr = (t_tcphdr*)(buffer + (iphdr->ihl << 2));

    printf("\nReceived TCP packet\n");

    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&iphdr->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&iphdr->daddr));

    printf("Source port: %d\n", ntohs(tcphdr->th_sport));
    printf("Destination port: %d\n", ntohs(tcphdr->th_dport));

    printf("Sequence number: %u\n", ntohl(tcphdr->th_seq));
    printf("Acknowledge number: %u\n", ntohl(tcphdr->ack_seq));

    printf("Flags: ");
    if(tcphdr->th_flags & TH_FIN) printf("FIN ");
    if(tcphdr->th_flags & TH_SYN) printf("SYN ");
    if(tcphdr->th_flags & TH_RST) printf("RST ");
    if(tcphdr->th_flags & TH_PUSH) printf("PSH ");
    if(tcphdr->th_flags & TH_ACK) printf("ACK ");
    if(tcphdr->th_flags & TH_URG) printf("URG ");
    printf("\n");
}

byte tcp_probe(const char* const dst_host, const ushort dst_port,
               const char** const flags) {

    static const ushort src_ports[] = {

        32768, 49152, 65535, 20, 80, 88, 139, 389, 443, 3389
    };
    static const ubyte src_ports_size = sizeof(src_ports) / SHORT_SIZE;
    static ubyte src_port_idx = 0;

    t_socket sock = new_socket(dst_host, dst_port, IPPROTO_TCP);
    if(sock.fd == -1) return EXIT_FAILURE;

    byte payload[BUFFER_SIZE] = {0};

    const uint src_ip = data.self.addr;
    const uint dst_ip = sock.addr.sin_addr.s_addr;

    t_iphdr* const iphdr = (t_iphdr*)payload;
    ip_hdr(iphdr, IPPROTO_TCP, src_ip, dst_ip);

    const ubyte iphdr_size = iphdr->ihl << 2;
    ushort size = iphdr_size + T_TCPHDR_SIZE;

    t_tcphdr* const tcphdr = (t_tcphdr*)(payload + iphdr_size);
    tcp_hdr(tcphdr, flags, src_ports[src_port_idx], dst_port);

    ubyte body_size = 0;
    byte* const body = payload + size;

    if(data.opt.firewall || data.opt.ids) {

        body_size += MIN_DATA_SIZE + (rand() % RANGE_DATA_SIZE);
        size += body_size;
    }
    for(ubyte x = 0; x < body_size; x++) body[x] = rand() % UCHAR_MAX;
    size -= iphdr_size;

    tcp_checksum(iphdr, tcphdr, body, body_size);
    const ubyte retries = data.opt.firewall
                          ? src_ports_size * REQ_RETRIES
                          : REQ_RETRIES;
    bool failed = NO;
    byte buffer[BUFFER_SIZE] = {0};
    for(ubyte x = 0; x < retries; x++) {

        if(new_probe(&sock, iphdr, size, payload, buffer) != EXIT_SUCCESS) {
            failed = YES;
            break;
        }
        print_tcp_response(buffer);
        break;
    }
    close(sock.fd);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
