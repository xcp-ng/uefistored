#ifndef __H_COMMON
#define __H_COMMON

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int _logfd;

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
    } while ( 0 )

#define WARNING(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd, "WARNING: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
    } while ( 0 )

#define DEBUG(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            varstored_dprintf(_logfd, "DEBUG: "  __VA_ARGS__);   \
    } while ( 0 )

#define DPRINTF(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            dprintf(_logfd, __VA_ARGS__);   \
    } while ( 0 )


#if 1
#define TRACE()  DEBUG("%s: %d\n", __func__, __LINE__)
#else
#define TRACE() do { } while ( 0 )
#endif

#endif
