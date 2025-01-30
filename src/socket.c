#include "../include/header.h"

extern t_nmap data;

uint16_t checksum(const uint16_t* ptr, const uint16_t size) {

    uint32_t sum = 0;
    uint16_t count = size >> 1;

    while(count--) sum += *ptr++;
    if(size & 1) sum += *(uint8_t*)ptr;

    while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
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
    return sock;
}

static void* send_probe(t_send* const av) {

    usleep(FRAGMENT_INTERVAL);
    uint16_t fragment_size = av->size;
    uint8_t fragment_count = 1;
    bool decoy = NO;

    if(data.opt.flags & FIREWALL_CARE || data.opt.flags & IDS_CARE) {

        fragment_size = 8;
        fragment_count = av->size / fragment_size;
        if(av->size % fragment_size) fragment_count++;

        if(data.opt.flags & IDS_CARE) decoy = YES;
    }
    (void)decoy; // TODO: decoy

    const uint16_t iphdr_size = av->iphdr->ihl << 2;
    const uint16_t send_size = iphdr_size + fragment_size;

    int8_t payload[send_size];
    memset(payload, 0, send_size);
    memcpy(payload, av->iphdr, iphdr_size);

    t_iphdr* const iphdr = (t_iphdr*)payload;
    iphdr->tot_len = htons(send_size);

    int8_t* const body = payload + iphdr_size;
    const int8_t* const src = av->buffer + iphdr_size;

    const t_sockaddr* const addr = (t_sockaddr*)&av->sock->addr;

    uint16_t offset;
    for(uint8_t x = 0; x < fragment_count; x++) {

        offset = x * fragment_size;
        iphdr->frag_off = htons(offset >> 3);

        if(x < fragment_count - 1) iphdr->frag_off |= htons(IP_MF);

        iphdr->check = checksum((uint16_t*)payload, iphdr_size);
        memcpy(body, src + offset, fragment_size);

        if(sendto(av->sock->fd, payload, send_size,
                  0, addr, T_SOCKADDR_SIZE) == -1) {

            perror("sendto");
            break;
        }
        if(x < fragment_count - 1) usleep(FRAGMENT_INTERVAL);
    }
    return NULL;
}

int8_t new_probe(t_socket* const sock,
                 t_iphdr* const iphdr,
                 const uint16_t send_size,
                 int8_t* const send_buff,
                 int8_t* const recv_buff) {

    t_send av = {sock, iphdr, send_buff, send_size};
    pthread_t thread;
    if(pthread_create(&thread, NULL, (void*(*)(void*))send_probe, &av) != 0) {

        perror("pthread_create");
        return EXIT_FAILURE;
    }
    if(recv(sock->fd, recv_buff, BUFFER_SIZE, 0) == -1) {

        perror("recv");
        pthread_join(thread, NULL);
        return EXIT_FAILURE;
    }
    pthread_join(thread, NULL);
    return EXIT_SUCCESS;
}
