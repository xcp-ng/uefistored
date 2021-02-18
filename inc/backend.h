#ifndef __H_BACKEND__
#define __H_BACKEND__

#include "xapi.h"
#include "variable.h"

struct backend {
    int (*init)(bool resume);
    int (*notify)(void);
    void (*cleanup)(void);
    int (*parse_arg)(char *arg);
    int (*save)(void);
    int (*set)(void);
};

extern struct backend *backend;

static inline int backend_parse_arg(char *arg)
{
    if (!backend) {
        fprintf(stderr, "Argument --backend must be passed before --arg\n");
        exit(1);
    }

    if (backend->parse_arg)
        return backend->parse_arg(optarg);

    return 0;
}

static inline int backend_notify(void)
{
    if (backend && backend->notify)
        return backend->notify();

    return 0;
}

#define DEFINE_BACKEND_CHECKED_CALL(fn)         \
static inline void backend_##fn(void)                  \
{                                               \
    if (backend && backend->fn) {               \
        backend->fn();                          \
    }                                           \
}

static inline int backend_init(bool resume)
{
    if (backend && backend->init)
        return backend->init(resume);

    return 0;
}

/* backend_save */
DEFINE_BACKEND_CHECKED_CALL(save);

/* backend_set */
DEFINE_BACKEND_CHECKED_CALL(set);

/* backend_cleanup */
DEFINE_BACKEND_CHECKED_CALL(cleanup);

#endif /* __H_BACKEND__ */
