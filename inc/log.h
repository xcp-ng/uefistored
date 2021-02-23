#ifndef __H_LOG__
#define __H_LOG__

#include <errno.h>

#include "common.h"
#include "variable.h"

enum loglevel {
    LOGLEVEL_ERROR,
    LOGLEVEL_WARNING,
    LOGLEVEL_INFO,
    LOGLEVEL_DEBUG,
};

extern const enum loglevel loglevel;

#define ERROR(...)                                                             \
    do {                                                                       \
        if (loglevel >= LOGLEVEL_ERROR) {                                      \
            fprintf(stderr, "uefistored:ERROR: " __VA_ARGS__);                 \
            fflush(stderr);                                                    \
        }                                                                      \
    } while (0)

#define WARNING(...)                                                           \
    do {                                                                       \
        if (loglevel >= LOGLEVEL_WARNING) {                                    \
            fprintf(stderr, "uefistored:WARNING: " __VA_ARGS__);               \
            fflush(stderr);                                                    \
        }                                                                      \
    } while (0)

#define INFO(...)                                                              \
    do {                                                                       \
        if (loglevel >= LOGLEVEL_INFO) {                                       \
            fprintf(stdout, "uefistored:INFO: " __VA_ARGS__);                  \
            fflush(stdout);                                                    \
        }                                                                      \
    } while (0)

#ifdef DEBUG
#define DBG(...)                                                               \
    do {                                                                       \
        if (loglevel >= LOGLEVEL_DEBUG) {                                      \
            fprintf(stdout, "uefistored:DEBUG:%s:%d: ", __func__, __LINE__);   \
            fprintf(stdout, __VA_ARGS__);                                      \
            fflush(stdout);                                                    \
        }                                                                      \
    } while (0)

#define DPRINTF(...)                                                           \
        if (loglevel >= LOGLEVEL_DEBUG) {                                      \
            fprintf(stdout, __VA_ARGS__)                                       \
            fflush(stdout);                                                    \
        }                                                                      \

static inline void _dprint_data(const void *data, size_t datasz)
{
    const uint8_t *p = data;
    size_t i;

    if (!data)
        return;

    DPRINTF("data(%lu)=[", datasz);
    for (i = 0; i < datasz; i++) {
        DPRINTF("0x%02x ", p[i]);

        if (i < datasz - 1)
            DPRINTF(", ");
    }
    DPRINTF("]\n");
}

#define dprint_data(data, datasz) _dprint_data(data, datasz)

void _dprint_variable(const variable_t *var);
#define dprint_variable _dprint_variable
void _dprint_variable_list(const variable_t *vars, size_t n);
#define dprint_variable_list _dprint_variable_list
#define dprint_name _dprint_name
void _dprint_name(const UTF16 *name, size_t namesz);

#else
#define DBG(...) do { } while(0)
#define DPRINTF(...) do { } while(0)
#define dprint_data(...) do { } while(0)
#define dprint_variable_list(...) do { } while(0)
#define dprint_variable(...) do { } while(0)

#define dprint_name(...) do { } while(0)

#endif

#endif // __H_LOG__
