#include "../include/header.h"

extern t_nmap data;

t_socket sock_raw(const char* const host, const ushort port,
                  const int protocol) {

    t_socket sock = {0};
    sock.fd = socket(AF_INET, SOCK_RAW, protocol);
    if(sock.fd == -1) {

        perror("socket(AF_INET, SOCK_RAW)");
        free(sock);
        return NULL;
    }
    //int flag = 1;
    //if(setsockopt(sock.fd, IPPROTO_IP, IP_HDRINCL, &flag, INT_SIZE) == -1) {

    //    perror("setsockopt(IP_HDRINCL)");
    //    close(sock.fd);
    //    free(sock);
    //    return NULL;
    //}
    sock.addr.sin_family = AF_INET;
    sock.addr.sin_port = htons(port);
    sock.addr.sin_addr.s_addr = inet_addr(host);
    return sock;
}
