#include "../include/header.h"

extern t_nmap data;

ushort checksum(const ushort* ptr, const ubyte nbytes) {

    uint sum = 0;
    ushort count = nbytes >> 1;

    while(count--) sum += *ptr++;
    if(nbytes & 1) sum += *(ubyte*)ptr;

    while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

t_socket new_socket(const char* const host, const ushort port,
                    const int protocol) {

    static const t_timeval timeout = {0, REQ_TIMEOUT};
    t_socket sock = {0};

    sock.fd = socket(AF_INET, SOCK_RAW, protocol);
    if(sock.fd == -1) {

        perror("socket(AF_INET, SOCK_RAW)");
        return sock;
    }
    //int flag = 1;
    //if(setsockopt(sock.fd, IPPROTO_IP, IP_HDRINCL, &flag, INT_SIZE) == -1) {

    //    perror("setsockopt(IP_HDRINCL)");
    //    close(sock.fd);
    //    sock.fd = -1;
    //    return sock;
    //}
    if(setsockopt(sock.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, T_TIMEVAL_SIZE) == -1) {

        perror("setsockopt(SO_RCVTIMEO)");
        close(sock.fd);
        sock.fd = -1;
        return sock;
    }
    sock.addr.sin_family = AF_INET;
    sock.addr.sin_port = htons(port);
    sock.addr.sin_addr.s_addr = inet_addr(host);
    return sock;
}

static void* send_probe(t_send* const av) {

    bool decoy = NO;
    ushort fragment_size = av->size;
    ubyte fragment_count = 1;

    if(data.opt.firewall || data.opt.ids) {

        if(data.opt.ids) decoy = YES;
        fragment_size = 8;
        fragment_count = av->size / fragment_size;
        if(av->size % fragment_size) fragment_count++;
    }
    (void)decoy;
    // TODO: decoy
    const ubyte iphdr_size = av->iphdr->ihl << 2;
    const ubyte send_size = iphdr_size + fragment_size;

    byte send_buff[send_size];
    memset(send_buff, 0, send_size);
    memcpy(send_buff, av->iphdr, iphdr_size);

    t_iphdr* ptr = (t_iphdr*)send_buff;
    ptr->tot_len = htons(send_size);

    ushort offset;
    for(ubyte x = 0; x < fragment_count; x++) {

        offset = x * fragment_size;
        ptr->frag_off = htons(offset >> 3);
        if(x < fragment_count - 1) ptr->frag_off |= htons(IP_MF);

        ptr->check = checksum((ushort*)send_buff, iphdr_size);
        memcpy(send_buff + iphdr_size,
               av->payload + offset + iphdr_size, fragment_size);

        if(sendto(av->sock->fd, send_buff, send_size, 0,
                  (t_sockaddr*)&av->sock->addr, T_SOCKADDR_IN_SIZE) == -1) {

            perror("sendto");
            return NULL;
        }
        if(x < fragment_count - 1) usleep(100000);
    }
    return NULL;
}

byte new_probe(t_socket* const sock,
               t_iphdr* const iphdr,
               const ushort size,
               byte* const payload,
               byte* const recv_buff) {

    t_send av = {sock, iphdr, size, payload};
    pthread_t thread;
    if(pthread_create(&thread, NULL, (void*(*)(void*))send_probe, &av) != 0) {

        perror("pthread_create");
        return EXIT_FAILURE;
    }
    if(recv(sock->fd, recv_buff, BUFFER_SIZE, 0) == -1) {

        perror("recv");
        return EXIT_FAILURE;
    }
    pthread_join(thread, NULL);
    return EXIT_SUCCESS;
}
