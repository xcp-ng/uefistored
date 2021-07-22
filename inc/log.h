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

extern enum loglevel loglevel;

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

#define DBG(...)                                                               \
    do {                                                                       \
        if (loglevel >= LOGLEVEL_DEBUG) {                                      \
            fprintf(stdout, "uefistored:DEBUG:%s:%d: ", __func__, __LINE__);   \
            fprintf(stdout, __VA_ARGS__);                                      \
            fflush(stdout);                                                    \
        }                                                                      \
    } while (0)

#define DPRINTF(...)                                                           \
    do {                                                                       \
        if (loglevel >= LOGLEVEL_DEBUG) {                                      \
            fprintf(stdout, __VA_ARGS__);                                      \
            fflush(stdout);                                                    \
        }                                                                      \
    } while ( 0 )

void dprint_data(const void *data, size_t datasz);
void dprint_variable(const variable_t *var);
void dprint_variable_list(const variable_t *vars, size_t n);
void dprint_name(const UTF16 *name, size_t namesz);
void logging_init(void);

#endif // __H_LOG__
