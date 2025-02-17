#include "discovery.h"

t_host_info *detect_host_status(char **hosts, int count) {
	t_host_info *results = malloc(count * sizeof(t_host_info));
	int icmp_result = -2;
	int tcp_result = -2;

	for (int i = 0; i < count; i++) {
		results[i].host = hosts[i];
		icmp_result = icmp_probe(hosts[i]);
		//tcp_result = send_tcp_request(hosts[i]);
		if (icmp_result || tcp_result)
			results[i].status = HOST_UP;
		else
			results[i].status = HOST_DOWN;
	}

	return results;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		if (DEBUG_LEVEL) { printf("[DEBUG]Usage: %s <host1> <host2> ...\n", argv[0]); };
		return 1;
	}

	char **hosts = &argv[1];
	int count = argc - 1;

	t_host_info *results = detect_host_status(hosts, count);

	for (int i = 0; i < count; i++) {
		if (DEBUG_LEVEL) { printf("[DEBUG]Host: %s - Status: %s\n", results[i].host, results[i].status == HOST_UP ? "UP" : "PROBABLY DOWN"); };
	}

	free(results);
	return 0;
}