#include "../../include/header.h"

extern t_nmap data;

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

uint32_t get_host_ip() {

    t_ifaddrs* ifaddr;
    t_ifaddrs* ifa;

    char ip[INET_ADDRSTRLEN] = {0};
    if(getifaddrs(&ifaddr) == -1) {

        perror("getifaddrs");
        return 0;
    }
    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {

        if(!ifa->ifa_addr) continue;
        if(ifa->ifa_addr->sa_family != AF_INET) continue;
        if(ifa->ifa_flags & IFF_LOOPBACK) continue;

        void* addr = &((t_sockaddr_in*)ifa->ifa_addr)->sin_addr;
        if(inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN) != NULL) break;

        data.code = errno;
        perror("inet_ntop");
        freeifaddrs(ifaddr);
        return 0;
    }
    freeifaddrs(ifaddr);
    return inet_addr(ip);
}
