#include "../../include/header.h"

extern t_nmap data;

void default_ports() {

    for(uint16_t port = 1; port <= 1024; port++)
        data.ports[port - 1] = port;
}

static int8_t parse_range(const uint16_t idx,
                          char** const buffer,
                          uint16_t* const ports,
                          uint16_t* const offset) {

    char* token = strtok(buffer[idx], "-");
    if(!token) {

        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;
    }
    const uint16_t start = atoi(token);

    token = strtok(NULL, "-");
    if(!token) {

        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;
    }
    const uint16_t end = atoi(token);

    if(!start || !end || start > end) {

        data.code = EINVAL;
        error(strerror(EINVAL));
        return FAILURE;
    }
    ports[idx] = start;

    for(uint16_t port = start + 1; port <= end; port++) {

        if(*offset == BUFFER_SIZE) {

            data.code = E2BIG;
            error(strerror(E2BIG));
            return FAILURE;
        }
        ports[(*offset)++] = port;
    }
    return SUCCESS;
}

static uint16_t* parse_ports(char* const arg) {

    char** const buffer = read_arg(arg);
    if(!buffer) return NULL;

    static const uint32_t buffer_size = (BUFFER_SIZE + 1) * PTR_SIZE;

    uint16_t* const ports = malloc(buffer_size);
    if(!ports) {

        for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);

        data.code = errno;
        error(strerror(errno));
        return NULL;
    }
    memset(ports, 0, buffer_size);

    uint16_t size = 0;
    while(buffer[size]) size++;

    uint16_t offset = size;

    for(uint16_t x = 0; x < size; x++) {

        if(!strchr(buffer[x], '-')) {

            ports[x] = atoi(buffer[x]);
            if(ports[x]) continue;

            data.code = EINVAL;
            error(strerror(EINVAL));
            break;
        }
        if(parse_range(x, buffer, ports, &offset) == FAILURE) break;
    }
    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    if(data.code) {

        free(ports);
        return NULL;
    }
    return ports;
}

int8_t new_ports(char* const arg) {

    static uint16_t idx = 0;

    uint16_t* const buffer = parse_ports(arg);
    if(!buffer) return FAILURE;

    bool duplicate;

    for(uint16_t x = 0; buffer[x]; x++) {

        if(idx == MAX_PORTS) {

            data.code = E2BIG;
            error(strerror(E2BIG));
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

    return data.code ? FAILURE : SUCCESS;
}
