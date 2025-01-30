#include "../../include/header.h"

extern t_nmap data;

static void tcp_hdr(t_tcphdr* const hdr,
                    const uint8_t flags,
                    const uint16_t src_port,
                    const uint16_t dst_port) {

    hdr->th_flags = flags;
    hdr->th_sport = htons(src_port);
    hdr->th_dport = htons(dst_port);

    hdr->th_off = 5;
    hdr->th_win = htons(5840);
    hdr->th_seq = rand();
    //hdr->ack_seq = 0;
}

static void tcp_checksum(t_iphdr* const iphdr,
                         t_tcphdr* const tcphdr,
                         const uint8_t* const body,
                         const uint8_t body_size) {

    static t_pseudo_iphdr pseudo_iphdr = {0};
    pseudo_iphdr.protocol = IPPROTO_TCP;

    pseudo_iphdr.saddr = iphdr->saddr;
    pseudo_iphdr.daddr = iphdr->daddr;
    pseudo_iphdr.len = htons(T_TCPHDR_SIZE + body_size);

    uint8_t buffer[BUFFER_SIZE] = {0};
    uint16_t size = T_PSEUDO_IPHDR_SIZE;

    memcpy(buffer, &pseudo_iphdr, size);
    memcpy(buffer + size, tcphdr, T_TCPHDR_SIZE);
    size += T_TCPHDR_SIZE;

    memcpy(buffer + size, body, body_size);
    size += body_size;
    tcphdr->th_sum = checksum((uint16_t*)buffer, size);
}

void print_tcp(const uint8_t* const buffer) {

    printf(GREEN"\n"BOLD"Received TCP packet"RESET);
    printf(GREEN"\n"BOLD"===================\n"RESET);
    const t_iphdr* const iphdr = (t_iphdr*)buffer;
    const uint16_t ip_size = iphdr->ihl << 2;

    const t_tcphdr* const tcphdr = (t_tcphdr*)(buffer + ip_size);
    const uint16_t tcp_size = tcphdr->th_off << 2;

    const uint16_t size = ntohs(iphdr->tot_len);
    printf("Total Length: %d bytes\n", size);

    const uint8_t* const body = buffer + ip_size + tcp_size;
    const uint16_t body_size = size - ip_size - tcp_size;

    printf(BOLD"\n==== IP Header ====\n"RESET);
    printf("Version:");
    if(iphdr->version == 4) printf(" IPv4\n");
    else if(iphdr->version == 6) printf(" IPv6\n");
    else printf(" UNKNOWN (%d)\n", iphdr->version);

    printf("Source IP: %s\n", inet_ntoa(*(t_in_addr*)&iphdr->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(t_in_addr*)&iphdr->daddr));

    printf("Protocol:");
    if(iphdr->protocol == IPPROTO_TCP) printf(" TCP\n");
    else if(iphdr->protocol == IPPROTO_UDP) printf(" UDP\n");
    else if(iphdr->protocol == IPPROTO_ICMP) printf(" ICMP\n");
    else printf(" UNKNOWN (%d)\n", iphdr->protocol);

    printf("Time to Live: %d\n", iphdr->ttl);
    printf("Identification: 0x%04X\n", ntohs(iphdr->id));
    printf("Fragment Offset: %d\n", ntohs(iphdr->frag_off) & 0x1FFF);
    printf("Type of Service: 0x%02X\n", iphdr->tos);
    printf("Length: %d bytes\n", ip_size);
    printf("Checksum: 0x%04X\n", ntohs(iphdr->check));

    printf(BOLD"\n==== TCP Header ===\n"RESET);
    printf("Flags: ");
    if(tcphdr->th_flags & TH_FIN) printf("FIN ");
    if(tcphdr->th_flags & TH_SYN) printf("SYN ");
    if(tcphdr->th_flags & TH_RST) printf("RST ");
    if(tcphdr->th_flags & TH_PUSH) printf("PSH ");
    if(tcphdr->th_flags & TH_ACK) printf("ACK ");
    if(tcphdr->th_flags & TH_URG) printf("URG ");
    printf("\n");
    printf("Source Port: %d\n", ntohs(tcphdr->th_sport));
    printf("Destination Port: %d\n", ntohs(tcphdr->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcphdr->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcphdr->ack_seq));
    printf("Window Size: %d\n", ntohs(tcphdr->th_win));
    printf("Urgent Pointer: %d\n", ntohs(tcphdr->th_urp));
    printf("Length: %d bytes\n", tcp_size);
    printf("Checksum: 0x%04X\n", ntohs(tcphdr->th_sum));

    printf(BOLD"\n======= BODY ======\n"RESET);
    if(!body_size) {

        printf("Empty\n\n");
        return;
    }
    for(uint16_t x = 0; x < body_size; x++) {

        if(x && x % 16 == 0) printf("\n");
        printf("%02X ", body[x]);
    }
    printf("\n");
    for(uint16_t x = 0; x < body_size; x++) {

        if(x && x % 16 == 0) printf("\n");
        if(body[x] >= 32 && body[x] <= 126) printf("%2c ", body[x]);
        else printf(" . ");
    }
    printf("\n\n");
}

int8_t tcp_probe(const char* const dst_host,
                 const uint16_t dst_port,
                 const uint8_t flags) {

    static const uint16_t src_ports[] = {

        32768, 49152, 65535, 20, 80, 88, 139, 389, 443, 3389
    };
    static const uint8_t src_ports_size = sizeof(src_ports) / INT16_SIZE;
    static uint8_t src_port_idx = 0;

    t_socket sock = new_socket(dst_host, dst_port, IPPROTO_TCP);
    if(sock.fd == -1) return EXIT_FAILURE;

    uint8_t send_buff[BUFFER_SIZE] = {0};

    const uint src_ip = data.opt.src_ip;
    const uint dst_ip = sock.addr.sin_addr.s_addr;

    t_iphdr* const iphdr = (t_iphdr*)send_buff;
    ip_hdr(iphdr, IPPROTO_TCP, src_ip, dst_ip);

    const uint8_t iphdr_size = iphdr->ihl << 2;
    uint16_t size = iphdr_size + T_TCPHDR_SIZE;

    t_tcphdr* const tcphdr = (t_tcphdr*)(send_buff + iphdr_size);
    tcp_hdr(tcphdr, flags, src_ports[src_port_idx], dst_port);

    uint8_t body_size = 0;
    uint8_t* const body = send_buff + size;

    if(data.opt.flags & FIREWALL_CARE || data.opt.flags & IDS_CARE) {

        body_size += MIN_BODY_SIZE + (rand() % RANGE_BODY_SIZE);
        size += body_size;
    }
    for(uint8_t x = 0; x < body_size; x++) body[x] = rand() % UCHAR_MAX;
    size -= iphdr_size;
    tcp_checksum(iphdr, tcphdr, body, body_size);

    const uint8_t retries = data.opt.flags & FIREWALL_CARE
                            ? src_ports_size * REQ_RETRIES
                            : REQ_RETRIES;
    bool failed = NO;
    uint8_t recv_buff[BUFFER_SIZE] = {0};
    for(uint8_t x = 0; x < retries; x++) {

        if(new_probe(&sock, iphdr, size,
                     send_buff, recv_buff) != EXIT_SUCCESS) {
            failed = YES;
            break;
        }
        print_tcp(recv_buff);
        break;
        if(!(data.opt.flags & FIREWALL_CARE)) continue;

        src_port_idx++;
        if(src_port_idx == src_ports_size) src_port_idx = 0;
        tcphdr->th_sport = htons(src_ports[src_port_idx]);
    }
    close(sock.fd);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
