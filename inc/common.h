#ifndef __H_COMMON
#define __H_COMMON

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>

#include "uefitypes.h"

#define DEBUG_MODE 1

#define min(x, y) ((x) < (y) ? (x) : (y))

#define MAX_VAR_COUNT 512
#define MAX_VARNAME_SZ 128 
#define MAX_VARDATA_SZ 1024

#define VARSTORED_ERROR 1
#define VAR_NOT_FOUND (-10)

/* OVMF XenVariable loads 16 pages of shared memory to pass varstored the command */
#define PAGE_SIZE (4<<10)
#define SHMEM_PAGES 16
#define SHMEM_SIZE (SHMEM_PAGES * PAGE_SIZE)


typedef struct {
    size_t namesz;
    UTF16 name[MAX_VARNAME_SZ];
    size_t datasz;
    uint8_t data[MAX_VARDATA_SZ];
    uint32_t attrs;
    EFI_GUID guid;
} variable_t;

#define for_each_variable(vars, var) \
    for ( (var) = (vars); (var) <= &(vars)[sizeof((vars))/sizeof((vars)[0])]; (var)++ )

typedef struct {
    /* The name of the variable */
    uint8_t *variable;

    /* The length of the variable name */
    size_t variable_len;

    /* The value of the variable */
    uint8_t *data;

    /* The length of the value of the variable */
    size_t data_len;
} serializable_var_t;



void dprint_variable(variable_t *var);

#define USE_STREAM 1

uint64_t strlen16(UTF16 *str);
uint64_t strsize16(UTF16 *str);
int strcmp16(UTF16 *a, UTF16 *b);

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
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stderr, "ERROR: " __VA_ARGS__);       \
    } while ( 0 )

#define WARNING(...)                                                  \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd, "WARNING: " __VA_ARGS__);       \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stderr, "WARNING: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        if ( _logfd > 0 )                                                 \
            varstored_dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
        if (  USE_STREAM )                                                 \
            varstored_fprintf(stdout, "INFO: " __VA_ARGS__);       \
    } while ( 0 )

#define DEBUG(...)                                              \
    do {                                                        \
        if ( _logfd > 0 )                                             \
            varstored_dprintf(_logfd, "DEBUG: "  __VA_ARGS__);   \
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


#if 1
#define TRACE()  DEBUG("%s: %d\n", __func__, __LINE__)
#else
#define TRACE() do { } while ( 0 )
#endif

void uc2_ascii_safe(UTF16 *uc2, size_t uc2_len, char *ascii, size_t len);
void uc2_ascii(UTF16 *uc2, char *ascii, size_t len);
bool variable_is_empty(variable_t *);

extern char strbuf[512];

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


typedef int (*var_initializer_t)(variable_t *, size_t);

void dprint_data(void *data, size_t datalen);
variable_t *find_variable(UTF16 *name, variable_t variables[MAX_VAR_COUNT], size_t n);

#endif
