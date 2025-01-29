#include "../../include/header.h"

extern t_nmap data;

void default_ports() {

    const ushort ports[] = {

        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    };
    const size_t ports_size = sizeof(ports);

    memcpy(data.ports, ports, ports_size);
    data.opt.ports = ports_size / SHORT_SIZE;
}

static byte read_range(char* const buffer, ushort* const ports,
                       const ushort size) {

    char* token = strtok(buffer, "-");
    if(!token) {

        fprintf(stderr, "Error: invalid port range\n");
        return EXIT_FAILURE;
    }
    const ushort start = atoi(token);
    token = strtok(NULL, "-");
    if(!token) {

        fprintf(stderr, "Error: invalid port range\n");
        return EXIT_FAILURE;
    }
    const ushort end = atoi(token);
    if(!start || !end || start > end) {

        fprintf(stderr, "Error: invalid port range\n");
        return EXIT_FAILURE;
    }
    ushort idx = size - 1;
    for(ushort port = start; port <= end; port++) {

        if(idx == BUFFER_SIZE - 1) {

            fprintf(stderr, "Error: too many ports\n");
            return EXIT_FAILURE;
        }
        ports[idx++] = port;
    }
    return EXIT_SUCCESS;
}

static ushort* read_ports(char* const arg) {

    char** const buffer = read_arg(arg);
    if(!buffer) return NULL;

    ushort* const ports = malloc(BUFFER_SIZE * SHORT_SIZE);
    if(!ports) {

        for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);
        perror("malloc");
        return NULL;
    }
    ushort size = 0;
    for(ushort x = 0; buffer[x]; x++) size++;

    bool failed = NO;
    for(ushort x = 0; x < size; x++) {

        if(!strchr(buffer[x], '-')) {

            ports[x] = atoi(buffer[x]);
            if(ports[x]) continue;

            fprintf(stderr, "Error: invalid port '%s'\n", buffer[x]);
            failed = YES;
            break;
        }
        if(read_range(buffer[x], ports, size) == EXIT_SUCCESS) continue;
        failed = YES;
        break;
    }
    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    if(!failed) return ports;

    free(ports);
    return NULL;
}

byte new_ports(char* const optarg) {

    ushort* const buffer = read_ports(optarg);
    if(!buffer) return EXIT_FAILURE;

    ushort idx = data.opt.ports;
    bool failed = NO;
    bool duplicate;
    for(ushort x = 0; buffer[x]; x++) {

        if(idx >= MAX_PORTS) {

            fprintf(stderr, "Error: too many ports specified\n");
            failed = YES;
            break;
        }
        duplicate = NO;
        for(ushort y = 0; data.ports[y]; y++) {

            if(buffer[x] != data.ports[y]) continue;
            duplicate = YES;
            break;
        }
        if(duplicate) continue;
        data.ports[idx] = buffer[x];
        idx++;
    }
    free(buffer);
    data.opt.ports = idx;
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
