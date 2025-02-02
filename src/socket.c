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

        perror("socket(AF_INET, SOCK_RAW)");
        return sock;
    }
    if(setsockopt(sock.fd, SOL_SOCKET, SO_RCVTIMEO,
                  &timeout, T_TIMEVAL_SIZE) == -1) {

        perror("setsockopt(SO_RCVTIMEO)");
        close(sock.fd);
        sock.fd = -1;
        return sock;
    }
    if(setsockopt(sock.fd, IPPROTO_IP, IP_HDRINCL,
                  &ip_hdrincl, INT_SIZE) == -1) {

        perror("setsockopt(IP_HDRINCL)");
        close(sock.fd);
        sock.fd = -1;
        return sock;
    }
    sock.addr.sin_family = AF_INET;
    sock.addr.sin_port = htons(dst_port);
    sock.addr.sin_addr.s_addr = inet_addr(dst_host);

    if(ip_filter(sock.fd, sock.addr.sin_addr.s_addr) == -1) {

        perror("setsockopt(SO_ATTACH_FILTER)");
        close(sock.fd);
        sock.fd = -1;
        return sock;
    }
    return sock;
}

static void* send_probe(t_send* const av) {

    usleep(FRAGMENT_INTERVAL);

    t_iphdr* iphdr = (t_iphdr*)av->buffer;
    const uint8_t iphdr_size = iphdr->ihl << 2;

    uint8_t fragment_size, fragment_count, packet_size;
    if(data.opt.flags & FIREWALL_CARE || data.opt.flags & IDS_CARE) {

        const uint8_t size = av->headers_size - iphdr_size + av->body_size;
        fragment_count = size / FRAGMENT_SIZE;
        if(size % FRAGMENT_SIZE) fragment_count++;

        fragment_size = FRAGMENT_SIZE;
        packet_size = iphdr_size + fragment_size;
    } else {
        fragment_count = 1;
        packet_size = fragment_size = av->headers_size + av->body_size;
    }
    uint8_t payload[BUFFER_SIZE] = {0};
    memcpy(payload, iphdr, iphdr_size);

    iphdr = (t_iphdr*)payload;
    iphdr->tot_len = htons(packet_size);

    uint8_t* const body = payload + iphdr_size;
    const uint8_t* const src = av->buffer + iphdr_size;

    const t_sockaddr* const addr = (t_sockaddr*)&av->sock->addr;
    uint8_t offset;
    for(uint8_t x = 0; x < fragment_count; x++) {

        offset = x * fragment_size;
        iphdr->frag_off = htons(offset >> 3);

        if(x < fragment_count - 1) iphdr->frag_off |= htons(IP_MF);

        iphdr->check = checksum((uint16_t*)payload, iphdr_size);
        memcpy(body, src + offset, fragment_size);

        if(sendto(av->sock->fd, payload, packet_size,
                  0, addr, T_SOCKADDR_SIZE) == -1) {

            perror("sendto");
            break;
        }
        if(x < fragment_count - 1) usleep(FRAGMENT_INTERVAL);
    }
    return NULL;
}

int8_t new_probe(t_socket* const sock,
                 const uint8_t headers_size,
                 const uint8_t body_size,
                 uint8_t* const send_buff,
                 uint8_t* const recv_buff) {

    t_send av = {sock, send_buff, headers_size, body_size};
    pthread_t thread;
    if(pthread_create(&thread, NULL, (void*(*)(void*))send_probe, &av) != 0) {

        perror("pthread_create");
        return EXIT_FAILURE;
    }
    if(recv(sock->fd, recv_buff, BUFFER_SIZE, 0) == -1) {

        if(errno == EAGAIN) return EXIT_SUCCESS;
        pthread_join(thread, NULL);
        return EXIT_FAILURE;
    }
    pthread_join(thread, NULL);
    return EXIT_SUCCESS;
}
