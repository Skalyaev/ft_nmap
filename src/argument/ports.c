#include "../../include/header.h"

extern t_nmap data;

void default_ports() {

    const uint16_t ports[] = {

        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    };
    memcpy(data.ports, ports, sizeof(ports));
}

static int8_t read_range(const uint16_t idx,
                         char** const buffer,
                         uint16_t* const ports,
                         uint16_t* const offset) {

    char* token = strtok(buffer[idx], "-");
    if(!token) {

        fprintf(stderr, "Error: invalid port range\n");
        return EXIT_FAILURE;
    }
    const uint16_t start = atoi(token);
    token = strtok(NULL, "-");
    if(!token) {

        fprintf(stderr, "Error: invalid port range\n");
        return EXIT_FAILURE;
    }
    const uint16_t end = atoi(token);
    if(!start || !end || start > end) {

        fprintf(stderr, "Error: invalid port range\n");
        return EXIT_FAILURE;
    }
    ports[idx] = start;
    for(uint16_t port = start + 1; port <= end; port++) {

        if(*offset == BUFFER_SIZE) {

            fprintf(stderr, "Error: too many ports\n");
            return EXIT_FAILURE;
        }
        ports[(*offset)++] = port;
    }
    return EXIT_SUCCESS;
}

static uint16_t* read_ports(char* const arg) {

    char** const buffer = read_arg(arg);
    if(!buffer) return NULL;

    static const uint32_t buffer_size = (BUFFER_SIZE + 1) * PTR_SIZE;

    uint16_t* const ports = malloc(buffer_size);
    if(!ports) {

        for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);

        perror("malloc");
        return NULL;
    }
    memset(ports, 0, buffer_size);

    uint16_t size = 0;
    while(buffer[size]) size++;

    uint16_t offset = size;
    bool failed = NO;
    for(uint16_t x = 0; x < size; x++) {

        if(!strchr(buffer[x], '-')) {

            ports[x] = atoi(buffer[x]);
            if(ports[x]) continue;

            fprintf(stderr, "Error: invalid port '%s'\n", buffer[x]);
            failed = YES;
            break;
        }
        if(read_range(x, buffer, ports, &offset) == EXIT_SUCCESS) continue;
        failed = YES;
        break;
    }
    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    if(!failed) return ports;

    free(ports);
    return NULL;
}

int8_t new_ports(char* const arg) {

    static uint16_t idx = 0;

    uint16_t* const buffer = read_ports(arg);
    if(!buffer) return EXIT_FAILURE;

    bool failed = NO;
    bool duplicate;
    for(uint16_t x = 0; buffer[x]; x++) {

        if(idx == MAX_PORTS) {

            fprintf(stderr, "Error: too many ports specified\n");
            failed = YES;
            break;
        }
        duplicate = NO;
        for(uint16_t y = 0; data.ports[y]; y++) {

            if(buffer[x] != data.ports[y]) continue;
            duplicate = YES;
            break;
        }
        if(duplicate) continue;
        data.ports[idx++] = buffer[x];
    }
    free(buffer);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
