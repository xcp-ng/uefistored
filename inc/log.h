#ifndef __H_LOG__
#define __H_LOG__

#include <errno.h>
#include "common.h"

extern int _logfd;
extern char strbuf[512];

/**
 * This function initializes the logging framework.
 */
void log_init(unsigned int domid);

/**
 * This function deinitializes the logging framework.
 */
void log_deinit(void);

#define uefistored_fprintf(stream, ...)                                        \
    do {                                                                       \
        fprintf(stream, __VA_ARGS__);                                          \
        fflush(stream);                                                        \
    } while (0)

#define ERROR(...)                                                             \
    do {                                                                       \
        if (_logfd > 0)                                                        \
            dprintf(_logfd, "ERROR: " __VA_ARGS__);                            \
        uefistored_fprintf(stderr, "ERROR: " __VA_ARGS__);                     \
    } while (0)

#define WARNING(...)                                                           \
    do {                                                                       \
        if (_logfd > 0)                                                        \
            dprintf(_logfd, "WARNING: " __VA_ARGS__);                          \
        uefistored_fprintf(stderr, "WARNING: " __VA_ARGS__);                   \
    } while (0)

#define INFO(...)                                                              \
    do {                                                                       \
        if (_logfd > 0)                                                        \
            dprintf(_logfd, "INFO: " __VA_ARGS__);                             \
        uefistored_fprintf(stdout, "INFO: " __VA_ARGS__);                      \
    } while (0)

#if 1
#define DDEBUG(...)                                                            \
    do {                                                                       \
        if (_logfd > 0) {                                                      \
            if (dprintf(_logfd, "DEBUG:%s:%d:", __func__, __LINE__) < 0)       \
                uefistored_fprintf(stderr, "failed to write to log file: %s\n", strerror(errno));   \
            if (dprintf(_logfd, __VA_ARGS__) < 0)                              \
                uefistored_fprintf(stderr, "failed to write to log file: %s\n", strerror(errno));   \
        }                                                                      \
                                                                               \
        uefistored_fprintf(stdout, "DEBUG:%s:%d: ", __func__, __LINE__);       \
        uefistored_fprintf(stdout, __VA_ARGS__);                               \
    } while (0)

#define DPRINTF(...)                                                           \
    do {                                                                       \
        if (_logfd > 0)                                                        \
            dprintf(_logfd, __VA_ARGS__);                                      \
        uefistored_fprintf(stdout, __VA_ARGS__);                               \
    } while (0)

static inline void dprint_data(const void *data, size_t datasz)
{
    const uint8_t *p = data;
    size_t i;

    if (!data)
        return;

    DPRINTF("data(%lu)=", datasz);
    for (i = 0; i < 8 && i < datasz; i++) {
        DPRINTF("0x%02x ", p[i]);
    }
}

#else
#error "No debug"
#define DDEBUG(...) do { } while(0)
#define DPRINTF(...) do { } while(0)
#define dprint_data(...) do { } while(0)
#endif

void dprint_variable(const variable_t *var);
void dprint_name(const UTF16 *name, size_t namesz);
void dprint_variable_list(const variable_t *vars, size_t n);

#endif // __H_LOG__
