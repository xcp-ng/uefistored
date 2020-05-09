#ifndef __H_COMMON
#define __H_COMMON

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#define USE_STREAM 1

uint64_t strlen16(char16_t *str);

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

#endif
