#include "../../include/header.h"

int8_t connect_scan(const char* const dst_host,
                    const uint16_t dst_port) {

    t_socket sock = {0};

    sock.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock.fd == -1) {

        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    sock.addr.sin_family = AF_INET;
    sock.addr.sin_port = htons(dst_port);

    if(inet_pton(AF_INET, dst_host, &sock.addr.sin_addr) != 1) {

        close(sock.fd);
        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    if(connect(sock.fd, (t_sockaddr*)&sock.addr, T_SOCKADDR_SIZE) == -1) {

        if(errno == ECONNREFUSED) {

            close(sock.fd);
            return PORT_CLOSED;
        }
        if(errno == ETIMEDOUT || errno == EHOSTUNREACH ||
           errno == ENETUNREACH || errno == EADDRNOTAVAIL) {

            close(sock.fd);
            return PORT_FILTERED;
        }
        close(sock.fd);
        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    close(sock.fd);
    return PORT_OPEN;
}
