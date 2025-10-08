#include "../../include/header.h"

extern t_nmap data;

char** read_arg(char* const arg) {

    char** const buffer = calloc(BUFFER_SIZE + 1, PTR_SIZE);
    if(!buffer) {

        data.code = errno;
        error(strerror(errno));
        return NULL;
    }
    char* token = strtok(arg, ",");

    for(uint16_t x = 0; token; x++) {

        if(x == BUFFER_SIZE) {

            data.code = E2BIG;
            error(strerror(E2BIG));
            break;
        }
        buffer[x] = strdup(token);
        if(!buffer[x]) {

            data.code = errno;
            error(strerror(errno));
            break;
        }
        token = strtok(NULL, ",");
    }
    if(data.code) {

        for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);
    }
    return buffer;
}

char** read_file(const char* const path) {

    FILE* const fd = fopen(path, "r");
    if(!fd) {

        data.code = errno;
        error(strerror(errno));
        return NULL;
    }
    char** const buffer = calloc(BUFFER_SIZE + 1, PTR_SIZE);
    if(!buffer) {

        fclose(fd);
        data.code = errno;
        error(strerror(errno));
        return NULL;
    }
    char tmp[BUFFER_SIZE + 1] = {0};
    uint16_t size;

    for(uint16_t x = 0; fgets(tmp, BUFFER_SIZE, fd); x++) {

        if(x == BUFFER_SIZE) {

            data.code = E2BIG;
            error(strerror(E2BIG));
            break;
        }
        size = strlen(tmp);
        if(size == BUFFER_SIZE - 1 && tmp[size - 1] != '\n') {

            data.code = E2BIG;
            error(strerror(E2BIG));
            break;
        }
        buffer[x] = strndup(tmp, size - 1);
        if(buffer[x]) continue;

        data.code = errno;
        error(strerror(errno));
        break;
    }
    fclose(fd);
    if(data.code) {

        for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
        free(buffer);
    }
    return buffer;
}
