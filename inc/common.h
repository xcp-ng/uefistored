#ifndef __H_COMMON__
#define __H_COMMON__

#define atomic_add(ptr, n)     ((void) __sync_fetch_and_add(ptr, n))

extern int _logfd;

static inline void set_logfd(int logfd)
{
    _logfd = logfd;
}

int init_log(void);

#define varstored_dprintf(fd, ...)                    \
    do {                                                \
        dprintf(fd, "varstored_initialize: ");        \
        dprintf(fd, __VA_ARGS__);                       \
    } while( 0 )

#define varstored_fprintf(stream, ...)                    \
    do {                                                \
        fprintf(stream, "varstored_initialize: ");        \
        fprintf(stream, __VA_ARGS__);                       \
        fflush(stream);                                     \
    } while( 0 )

#define ERROR(...)                                                  \
    do {                                                            \
        varstored_fprintf(stderr, "ERROR: " __VA_ARGS__);           \
        if ( _logfd )                                                 \
            varstored_dprintf(_logfd, "ERROR: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        varstored_fprintf(stdout,  "INFO: "   __VA_ARGS__);         \
        if ( _logfd )                                                 \
            varstored_dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
    } while ( 0 )

#if 1
#define DEBUG(...)                                              \
    do {                                                        \
        varstored_fprintf(stdout, "DEBUG: " __VA_ARGS__);       \
        if ( _logfd )                                             \
            varstored_dprintf(_logfd, "DEBUG: "  __VA_ARGS__);   \
    } while ( 0 )
#else
#define DEBUG(...) do { } while ( 0 )
#endif

#define TRACE()  DEBUG("%s: %d\n", __func__, __LINE__)

#endif
