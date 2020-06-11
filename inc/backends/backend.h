#ifndef __H_BACKEND_
#define __H_BACKEND_

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include "common.h"

enum backend_type {
    BACKEND_RAMDB,
    BACKEND_FILEDB,
};

struct backend {
    int (*init)(void);
    void (*deinit)(void);
    int (*get)(UTF16* name,
               void* dest, size_t dest_len,
               size_t *len, uint32_t *attrs);
    int (*set)(UTF16* name, void *val, size_t len, uint32_t attrs);
    void (*destroy)(void);
    int (*next)(variable_t *current, variable_t *next);
    void (*debug)(void);
};

extern struct backend ramdb_backend;
extern struct backend filedb_backend;

static const struct backend *backend = &ramdb_backend;

static inline int backend_init(enum backend_type type)
{

#if 0
    switch ( type )
    {
    case BACKEND_RAMDB:
        backend = &ramdb_backend;
        break;
    case BACKEND_FILEDB:
        backend = &filedb_backend;
        break;
    default:
        return -1;
    }
#endif

    if ( !backend || !backend->init )
        return -1;

    return backend->init();
}

static inline void backend_deinit(void)
{
    if ( !backend || !backend->deinit )
        return;

    backend->deinit();
}

static inline int backend_get(UTF16 *varname,
                void* dest, size_t dest_len,
                size_t *len, uint32_t *attrs)
{
    if ( !backend || !backend->get )
        return -1;

    return backend->get(varname,
                        dest, dest_len,
                        len, attrs);
}

static inline int backend_set(UTF16 *varname, void *val, size_t len, uint32_t attrs)
{
    if ( !backend || !backend->set )
        return -1;

    return backend->set(varname, val, len, attrs);
}

static inline void backend_destroy(void)
{
    if ( !backend || !backend->destroy )
        return;

    backend->destroy();
}

static inline int backend_next(variable_t *current, variable_t *next)
{
    if ( !backend || !backend->next )
        return -1;

    return backend->next(current, next);
}

#endif // __H_BACKEND_
