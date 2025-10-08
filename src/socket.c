#include "../include/header.h"

extern t_nmap data;

uint16_t checksum(const uint16_t* ptr, const uint8_t size) {

    uint32_t sum = 0;
    uint8_t count = size >> 1;

    while(count--) sum += *ptr++;
    if(size & 1) sum += *(uint8_t*)ptr;

    while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

static int ip_filter(const int fd, const uint32_t ip) {

    t_sock_filter code[] = {

        { LOAD_WORD, 0, 0, OFF_SRC_IP },
        { JUMP_EQUAL, 0, 1, htonl(ip) },
        { RETURN, 0, 0, ACCEPT },
        { RETURN, 0, 0, REJECT }
    };
    static const uint16_t size = sizeof(code) / T_SOCK_FILTER_SIZE;
    const t_sock_fprog bfp = {size, code};

    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                      &bfp, T_SOCK_FPROG_SIZE);
}

t_socket new_socket(const char* const dst_host,
                    const uint16_t dst_port,
                    const int protocol) {

    static const t_timeval timeout = {0, REQ_TIMEOUT};
    static const int ip_hdrincl = 1;

    t_socket sock = {0};

    sock.fd = socket(AF_INET, SOCK_RAW, protocol);
    if(sock.fd == -1) {

        setcode(errno);
        error(strerror(errno));
        return sock;
    }
    if(setsockopt(sock.fd, SOL_SOCKET, SO_RCVTIMEO,
                  &timeout, T_TIMEVAL_SIZE) == -1) {

        close(sock.fd);
        sock.fd = -1;

        setcode(errno);
        error(strerror(errno));
        return sock;
    }
    if(setsockopt(sock.fd, IPPROTO_IP, IP_HDRINCL,
                  &ip_hdrincl, INT_SIZE) == -1) {

        close(sock.fd);
        sock.fd = -1;

        setcode(errno);
        error(strerror(errno));
        return sock;
    }
    sock.addr.sin_family = AF_INET;
    sock.addr.sin_port = htons(dst_port);
    sock.addr.sin_addr.s_addr = inet_addr(dst_host);

    if(ip_filter(sock.fd, sock.addr.sin_addr.s_addr) == -1) {

        close(sock.fd);
        sock.fd = -1;

        setcode(errno);
        error(strerror(errno));
        return sock;
    }
    return sock;
}

static void* send_probe(const t_send* const av) {

    usleep(REQ_FRAGMENT_INTERVAL);

    t_iphdr* iphdr = (t_iphdr*)av->buffer;
    const uint8_t iphdr_size = iphdr->ihl << 2;

    uint8_t fragment_count;

    if(data.opt.flags & PACKET_FRAGMENT) {

        const uint8_t size = av->headers_size - iphdr_size;

        fragment_count = size / REQ_FRAGMENT_SIZE;
        if(size % REQ_FRAGMENT_SIZE) fragment_count++;
    }
    else fragment_count = 1;

    uint8_t payload[BUFFER_SIZE + 1] = {0};
    memcpy(payload, iphdr, iphdr_size);

    iphdr = (t_iphdr*)payload;

    uint8_t* const body = payload + iphdr_size;
    const uint8_t* const src = av->buffer + iphdr_size;

    const t_sockaddr* const addr = (t_sockaddr*)&av->sock->addr;
    const uint8_t payload_size = av->headers_size - iphdr_size;

    uint8_t offset;
    uint8_t fragment_size;
    uint16_t packet_size;

    for(uint8_t x = 0; x < fragment_count; x++) {

        if(data.opt.flags & PACKET_FRAGMENT) offset = x * REQ_FRAGMENT_SIZE;
        else offset = x * payload_size;

        if(data.opt.flags & PACKET_FRAGMENT) {

            if(x < fragment_count - 1) fragment_size = REQ_FRAGMENT_SIZE;
            else fragment_size = payload_size - offset;
        }
        else fragment_size = payload_size;

        iphdr->frag_off = htons((offset >> 3));
        if(x < fragment_count - 1) iphdr->frag_off |= htons(IP_MF);

        packet_size = iphdr_size + fragment_size;
        iphdr->tot_len = htons(packet_size);
        iphdr->check = 0;
        iphdr->check = checksum((uint16_t*)payload, iphdr_size);

        memcpy(body, src + offset, fragment_size);

        if(sendto(av->sock->fd, payload, packet_size,
                  0, addr, T_SOCKADDR_SIZE) == -1) {

            setcode(errno);
            error(strerror(errno));
            break;
        }
        if(x < fragment_count - 1) usleep(REQ_FRAGMENT_INTERVAL);
    }
    return NULL;
}

int8_t new_probe(t_socket* const sock,
                 const uint8_t headers_size,
                 uint8_t* const send_buff,
                 uint8_t* const recv_buff,
                 const uint8_t protocol,
                 const uint16_t src_port,
                 const uint16_t dst_port) {

    t_send av = {sock, send_buff, headers_size};
    pthread_t thread;

    if(pthread_create(&thread, NULL, (void*)send_probe, &av) == -1) {

        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    while(YES) {

        memset(recv_buff, 0, BUFFER_SIZE + 1);
        if(recv(sock->fd, recv_buff, BUFFER_SIZE, 0) == -1) {

            if(errno == EAGAIN) {

                pthread_join(thread, NULL);
                return SUCCESS;
            }
            pthread_join(thread, NULL);

            setcode(errno);
            error(strerror(errno));
            return FAILURE;
        }
        t_iphdr* iphdr = (t_iphdr*)recv_buff;
        if(iphdr->protocol != protocol) continue;

        const uint8_t iphdr_size = iphdr->ihl << 2;
        if(protocol == IPPROTO_TCP) {

            t_tcphdr* tcphdr = (t_tcphdr*)(recv_buff + iphdr_size);

            if(ntohs(tcphdr->th_dport) != src_port) continue;
            if(ntohs(tcphdr->th_sport) != dst_port) continue;
        }
        else if(protocol == IPPROTO_UDP) {

            t_udphdr* udphdr = (t_udphdr*)(recv_buff + iphdr_size);

            if(ntohs(udphdr->uh_dport) != src_port) continue;
            if(ntohs(udphdr->uh_sport) != dst_port) continue;
        }
        break;
    }
    pthread_join(thread, NULL);
    return getcode() ? FAILURE : SUCCESS;
}
