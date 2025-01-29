#include "../include/header.h"

extern t_nmap data;

void ip_hdr(t_iphdr* const hdr, const uint8_t protocol,
            const uint32_t saddr, const uint32_t daddr) {

    hdr->ihl = 5;
    hdr->version = 4;
    hdr->ttl = 64;

    hdr->saddr = saddr;
    hdr->daddr = daddr;
    hdr->protocol = protocol;
    hdr->id = htons(rand());
}

uint32_t get_host_ip() {

    t_ifaddrs* ifaddr;
    t_ifaddrs* ifa;

    char ip[INET_ADDRSTRLEN];
    if(getifaddrs(&ifaddr) == -1) {

        perror("getifaddrs");
        return 0;
    }
    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next) {

        if(!ifa->ifa_addr) continue;
        if(ifa->ifa_addr->sa_family != AF_INET) continue;
        if(ifa->ifa_flags & IFF_LOOPBACK) continue;

        void* addr = &((t_sockaddr_in*)ifa->ifa_addr)->sin_addr;
        if(inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN) == NULL) {

            perror("inet_ntop");
            freeifaddrs(ifaddr);
            return 0;
        }
        break;
    }
    freeifaddrs(ifaddr);
    return inet_addr(ip);
}
