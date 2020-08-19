#ifndef __H_LOG__
#define __H_LOG__

#include "common.h"

extern int _logfd;
extern char strbuf[512];

/**
 * This function initializes the logging framework.
 */
void log_init(const char *filename);

/**
 * This function deinitializes the logging framework.
 */
void log_deinit(void);

#define USE_STREAM 0

#define uefistored_fprintf(stream, ...)                    \
    do {                                                \
        fprintf(stream, __VA_ARGS__);                       \
        fflush(stream);                                     \
    } while( 0 )

#define ERROR(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            dprintf(_logfd, "ERROR: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            uefistored_fprintf(stderr, "ERROR: " __VA_ARGS__);       \
    } while ( 0 )

#define WARNING(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            dprintf(_logfd, "WARNING: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            uefistored_fprintf(stderr, "WARNING: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
        if (  USE_STREAM )                                                 \
            uefistored_fprintf(stdout, "INFO: " __VA_ARGS__);       \
    } while ( 0 )

#define DEBUG(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                       \
            dprintf(_logfd, "DEBUG:");                          \
            dprintf(_logfd, "%s:%d: ", __func__, __LINE__);      \
            dprintf(_logfd, __VA_ARGS__);            \
        if (  USE_STREAM )                                      \
            uefistored_fprintf(stdout, "DEBUG: " __VA_ARGS__);  \
    } while ( 0 )

#define DPRINTF(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            dprintf(_logfd, __VA_ARGS__);   \
        if (  USE_STREAM )                                                 \
            uefistored_fprintf(stdout, __VA_ARGS__);       \
    } while ( 0 )

#endif // __H_LOG__
