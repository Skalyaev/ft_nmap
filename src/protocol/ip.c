#include "../../include/header.h"

extern t_nmap data;

int8_t valid_host(const char* const host) {

    t_in_addr addr = {0};
    if(inet_pton(AF_INET, host, &addr) == 1) return YES;

    t_hostent* const hent = gethostbyname(host);
    return hent && hent->h_addrtype == AF_INET ? YES : NO;
}

int8_t get_src_ip() {

    if(data.opt.src_ip) return SUCCESS;

    t_ifaddrs* ifaddr;
    t_ifaddrs* ifa;

    char ip[INET_ADDRSTRLEN] = {0};
    if(getifaddrs(&ifaddr) == -1) {

        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {

        if(!ifa->ifa_addr) continue;
        if(ifa->ifa_addr->sa_family != AF_INET) continue;
        if(ifa->ifa_flags & IFF_LOOPBACK) continue;

        void* addr = &((t_sockaddr_in*)ifa->ifa_addr)->sin_addr;
        if(inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN) != NULL) break;

        freeifaddrs(ifaddr);
        setcode(errno);
        error(strerror(errno));
        return FAILURE;
    }
    freeifaddrs(ifaddr);

    data.opt.src_ip = inet_addr(ip);
    return SUCCESS;
}

void ip_hdr(t_iphdr* const hdr,
            const uint8_t protocol,
            const uint32_t src_ip,
            const uint32_t dst_ip) {

    hdr->protocol = protocol;
    hdr->saddr = src_ip;
    hdr->daddr = dst_ip;

    hdr->id = htons(rand());
    hdr->ttl = 64;
    hdr->ihl = 5;
    hdr->version = 4;
}
