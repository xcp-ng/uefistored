#ifndef __H_COMMON
#define __H_COMMON

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#define MAX_VARNAME_SZ 128 

typedef struct {
    uint8_t name[MAX_VARNAME_SZ];
    size_t namesz;
} variable_t;

typedef struct {
    /* The name of the variable */
    uint8_t *variable;

    /* The length of the variable name */
    size_t variable_len;

    /* The value of the variable */
    uint8_t *data;

    /* The length of the value of the variable */
    size_t data_len;
} serializable_var_t;

void dprint_variable(variable_t *var);

#define USE_STREAM 1

uint64_t strlen16(char16_t *str);
uint64_t strsize16(char16_t *str);

extern int _logfd;

/* OVMF XenVariable loads 16 pages of shared memory to pass varstored the command */
#define PAGE_SIZE (4<<10)
#define SHMEM_PAGES 16
#define SHMEM_SIZE (SHMEM_PAGES * PAGE_SIZE)

void set_logfd(int logfd);

#define varstored_dprintf(fd, ...)                    \
    do {                                                \
        dprintf(fd, __VA_ARGS__);                       \
    } while( 0 )

#define varstored_fprintf(stream, ...)                    \
    do {                                                \
        fprintf(stream, __VA_ARGS__);                       \
        fflush(stream);                                     \
    } while( 0 )

#define ERROR(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd, "ERROR: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stderr, "ERROR: " __VA_ARGS__);       \
    } while ( 0 )

#define WARNING(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd, "WARNING: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stderr, "WARNING: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stdout, "INFO: " __VA_ARGS__);       \
    } while ( 0 )

#define DEBUG(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            varstored_dprintf(_logfd, "DEBUG: "  __VA_ARGS__);   \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stdout, "DEBUG: " __VA_ARGS__);       \
    } while ( 0 )

#define DPRINTF(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            dprintf(_logfd, __VA_ARGS__);   \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stdout, __VA_ARGS__);       \
    } while ( 0 )


#if 1
#define TRACE()  DEBUG("%s: %d\n", __func__, __LINE__)
#else
#define TRACE() do { } while ( 0 )
#endif

void uc2_ascii_safe(void *uc2, size_t uc2_len, char *ascii, size_t len);
void uc2_ascii(void *uc2, char *ascii, size_t len);
#endif
