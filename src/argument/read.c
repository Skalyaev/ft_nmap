#include "../../include/header.h"

extern t_nmap data;

char** read_arg(char* const optarg) {

    char** const buffer = calloc(BUFFER_SIZE, PTR_SIZE);
    if(!buffer) {

        perror("calloc");
        return NULL;
    }
    char* token = strtok(optarg, ",");
    bool failed = NO;
    for(ushort x = 0; token; x++) {

        if(x == BUFFER_SIZE - 1) {

            fprintf(stderr, "Error: too many arguments\n");
            failed = YES;
            break;
        }
        buffer[x] = strdup(token);
        token = strtok(NULL, ",");
    }
    if(!failed) return buffer;

    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    return NULL;
}

char** read_file(const char* const file) {

    FILE* const fd = fopen(file, "r");
    if(!fd) {

        perror("fopen");
        return NULL;
    }
    char** const buffer = calloc(BUFFER_SIZE, PTR_SIZE);
    if(!buffer) {

        perror("calloc");
        fclose(fd);
        return NULL;
    }
    char data[BUFFER_SIZE] = {0};
    ushort size;

    bool failed = NO;
    for(ushort x = 0; fgets(data, BUFFER_SIZE, fd); x++) {

        if(x == BUFFER_SIZE  - 1) {

            fprintf(stderr, "Error: too many arguments\n");
            failed = YES;
            break;
        }
        size = strlen(data);
        if(data[size - 1] != '\n') {

            fprintf(stderr, "Error: line too long\n");
            failed = YES;
            break;
        }
        buffer[x] = strndup(data, size - 1);
    }
    fclose(fd);
    if(!failed) return buffer;

    for(ushort x = 0; buffer[x]; x++) free(buffer[x]);
    free(buffer);
    return NULL;
}
