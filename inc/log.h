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

void dprint_data(void *data, size_t datalen);
variable_t *find_variable(const UTF16 *name, variable_t variables[MAX_VAR_COUNT], size_t n);

#define varstored_fprintf(stream, ...)                    \
    do {                                                \
        fprintf(stream, __VA_ARGS__);                       \
        fflush(stream);                                     \
    } while( 0 )

#define ERROR(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            dprintf(_logfd, "ERROR: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stderr, "ERROR: " __VA_ARGS__);       \
    } while ( 0 )

#define WARNING(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            dprintf(_logfd, "WARNING: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stderr, "WARNING: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stdout, "INFO: " __VA_ARGS__);       \
    } while ( 0 )

#define DEBUG(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            dprintf(_logfd, "DEBUG: "  __VA_ARGS__);   \
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

/* Only useful for development */
#if 1
#define TRACE()  DEBUG("%s: %d\n", __func__, __LINE__)
#else
#define TRACE() do { } while ( 0 )
#endif

/**
 * dprint_vname -  Debug print a variable name
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */
#define dprint_vname(format, vn, ...) \
do { \
    uc2_ascii_safe(vn, strsize16(vn), strbuf, 512); \
    DEBUG(format, strbuf __VA_ARGS__); \
    memset(strbuf, '\0', 512); \
} while ( 0 )

#define eprint_vname(format, vn, ...) \
do { \
    uc2_ascii_safe(vn, strsize16(vn), strbuf, 512); \
    ERROR(format, strbuf __VA_ARGS__); \
    memset(strbuf, '\0', 512); \
} while( 0 )

#endif // __H_LOG__
