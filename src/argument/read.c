#include "../../include/header.h"

extern t_nmap data;

char** read_arg(char* const arg) {

    char** const buffer = calloc(BUFFER_SIZE + 1, PTR_SIZE);
    if(!buffer) {

        perror("calloc");
        return NULL;
    }
    char* token = strtok(arg, ",");
    bool failed = NO;
    for(uint16_t x = 0; token; x++) {

        if(x == BUFFER_SIZE) {

            fprintf(stderr, "Error: too many arguments\n");
            failed = YES;
            break;
        }
        buffer[x] = strdup(token);
        if(!buffer[x]) {

            perror("strdup");
            failed = YES;
            break;
        }
        token = strtok(NULL, ",");
    }
    if(!failed) return buffer;

    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    return NULL;
}

char** read_file(const char* const path) {

    FILE* const fd = fopen(path, "r");
    if(!fd) {

        perror("fopen");
        return NULL;
    }
    char** const buffer = calloc(BUFFER_SIZE + 1, PTR_SIZE);
    if(!buffer) {

        perror("calloc");
        fclose(fd);
        return NULL;
    }
    char data[BUFFER_SIZE + 1] = {0};
    uint16_t size;

    bool failed = NO;
    for(uint16_t x = 0; fgets(data, BUFFER_SIZE, fd); x++) {

        if(x == BUFFER_SIZE) {

            fprintf(stderr, "Error: too many arguments\n");
            failed = YES;
            break;
        }
        size = strlen(data);
        if(size == BUFFER_SIZE - 1 && data[size - 1] != '\n') {

            fprintf(stderr, "Error: line too long\n");
            failed = YES;
            break;
        }
        buffer[x] = strndup(data, size - 1);
        if(buffer[x]) continue;

        perror("strndup");
        failed = YES;
        break;
    }
    fclose(fd);
    if(!failed) return buffer;

    for(uint16_t x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    return NULL;
}
