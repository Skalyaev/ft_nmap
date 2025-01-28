#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include "define.h"
#include "struct.h"

void getargs(const int ac, char** const av);
void sigexit(const int sig);
byte setup_escape();
byte bye();

#endif
