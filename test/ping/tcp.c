#include "discovery.h"

void build_tcp_packet(char *packet, struct sockaddr_in target_address) {
	struct iphdr *ip_hdr;
	struct tcphdr *tcp_hdr;
	t_pseudo_header psh;
	
	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Building TCP packet\n");
	memset(packet, 0, sizeof(char) * 40);
	ip_hdr = (struct ip *)packet;
	tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));

	//Filling out IP header
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(sizeof(char) * 40);
	ip_hdr->ip_id = htons(54321);
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 255;
	ip_hdr->ip_p = IPPROTO_TCP;
	ip_hdr->ip_src.s_addr = INADDR_ANY;
	ip_hdr->ip_dst = target_address.sin_addr;
	ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

	ip_hdr->ihl = 5;
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ip_hdr->id = htons(54321);

	//Filling out pseudo-header for checksum
	psh.src = ip_hdr->ip_src.s_addr;
	psh.dst = ip_hdr->ip_dst.s_addr;
	psh.zero = 0;
	psh.proto = ip_hdr->ip_p;
	psh.len = htons(sizeof(struct tcphdr));

	//Filling out TCP header
	tcp_hdr->th_sport = htons(12345);
	tcp_hdr->th_dport = htons(80);
	tcp_hdr->th_seq = htonl(0);
	tcp_hdr->th_ack = htonl(0);
	tcp_hdr->th_off = 5;
	tcp_hdr->th_flags = TH_ACK;
	tcp_hdr->th_win = htons(8192);
	tcp_hdr->th_sum = 0;
	tcp_hdr->th_urp = 0;
	
	//Copy pseudo and TCP header into pseudo-packet and calculate checksum
	char pseudo_packet[sizeof(t_pseudo_header) + sizeof(struct tcphdr)];
	memcpy(pseudo_packet, &psh, sizeof(t_pseudo_header));
	memcpy(pseudo_packet + sizeof(t_pseudo_header), tcp_hdr, sizeof(struct tcphdr));

	tcp_hdr->th_sum = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Packet built\n");
}

t_host_status send_tcp_no_privileges(struct sockaddr_in target_addr) {
	int sockfd;

	//Opening standard TCP socket
	if (DEBUG_LEVEL >= LOW) printf("[TCP]Not privileged sending SYN\n");
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Socket creation failed");
		return HOST_DOWN;
	}

	struct timeval tv;
	tv.tv_sec = TIMEOUT_SEC;
	tv.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

	//Connecting to the target address
	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Connecting with TCP\n");
	if (connect(sockfd, (struct sockaddr *)&target_addr, sizeof(target_addr)) == 0) {
		if (DEBUG_LEVEL >= LOW) printf("[TCP]Connected\n");
		close(sockfd);
		return HOST_UP;
	}
	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Failed to connect\n");
	close(sockfd);
	return HOST_DOWN;
}

//Sends a TCP ping to the ip
t_host_status send_tcp_request(const char *ip) {
	struct sockaddr_in target_addr;
	int sockfd;
	char packet[40];

	//Filling out target info
	target_addr.sin_family = AF_INET;
	target_addr.sin_port = htons(80);
	target_addr.sin_addr.s_addr = inet_addr(ip);

	//Checking for privileges
	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Checking for privileges\n");
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) 
		return send_tcp_no_privileges(target_addr);
	if (DEBUG_LEVEL >= LOW) printf("[TCP]Privileged, sending ACK\n");
	
	//Building & sending packet if not privileged
	build_tcp_packet(&packet[0], target_addr);
	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Sending packet\n");
	if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
		perror("Raw packet send failed");
		if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Failed to send packet\n");
		close(sockfd);
		return HOST_DOWN;
	}
	if (DEBUG_LEVEL >= MEDIUM) printf("[TCP]Packet sent\n");
	close(sockfd);
	return HOST_UP;
}
