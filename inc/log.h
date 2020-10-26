#ifndef __H_LOG__
#define __H_LOG__

#include <errno.h>

#include "common.h"
#include "variable.h"

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

#if DEBUG
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

static inline void _dprint_data(const char *func, int lineno, const void *data, size_t datasz)
{
    const uint8_t *p = data;
    size_t i;

    if (!data)
        return;

    DPRINTF("%s:%d: data(%lu)=[", func, lineno, datasz);
    for (i = 0; i < datasz; i++) {
        DPRINTF("0x%02x ", p[i]);

        if (i < datasz - 1)
            DPRINTF(", ");
    }
    DPRINTF("]\n");
}

#define dprint_data(data, datasz) _dprint_data(__func__, __LINE__, data, datasz)

void _dprint_variable(const variable_t *var);
#define dprint_variable _dprint_variable
void _dprint_variable_list(const variable_t *vars, size_t n);
#define dprint_variable_list _dprint_variable_list
void dprint_name(const UTF16 *name, size_t namesz);

#else
#define DDEBUG(...) do { } while(0)
#define DPRINTF(...) do { } while(0)
#define dprint_data(...) do { } while(0)
#define dprint_variable_list(...) do { } while(0)
#define dprint_variable(...) do { } while(0)
#endif


#endif // __H_LOG__
