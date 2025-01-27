#ifndef DEFINE_H
#define DEFINE_H

#define MAX_THREADS 250
#define MAX_HOSTS 512
#define MAX_PORTS 1024

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define YES 1
#define NO 0

typedef char byte;
typedef unsigned char ubyte;
typedef unsigned char bool;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef struct option t_option;

#define BYTE_SIZE sizeof(byte)
#define SHORT_SIZE sizeof(short)
#define INT_SIZE sizeof(int)
#define LONG_SIZE sizeof(long)
#define SIZE_T_SIZE sizeof(size_t)
#define FLOAT_SIZE sizeof(float)
#define DOUBLE_SIZE sizeof(double)
#define PTR_SIZE sizeof(void*)

#define T_OPTION_SIZE sizeof(t_option)

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN "\033[1;36m"
#define WHITE "\033[1;37m"
#define RESET "\033[0m"

#endif
