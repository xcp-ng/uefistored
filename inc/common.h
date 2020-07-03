#ifndef __H_COMMON
#define __H_COMMON

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>

#include "uefitypes.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

#define MAX_VAR_COUNT 512
#define MAX_VARNAME_SZ 128 
#define MAX_VARDATA_SZ 1024

#define VARSTORED_ERROR 1
#define VAR_NOT_FOUND (-10)

#define PAGE_SIZE (4<<10)

/* OVMF XenVariable loads 16 pages of shared memory to pass varstored the command */
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
    for ( (var) = (vars); (var) < &((vars)[sizeof((vars))/sizeof((vars)[0])]); (var)++ )

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

uint64_t strlen16(const UTF16 *str);
uint64_t strsize16(const UTF16 *str);
int strcmp16(const UTF16 *a, const UTF16 *b);
int strncpy16(UTF16 *a, const UTF16 *b, const size_t n);

void uc2_ascii_safe(UTF16 *uc2, size_t uc2_len, char *ascii, size_t len);
void uc2_ascii(UTF16 *uc2, char *ascii, size_t len);
bool variable_is_empty(variable_t *);


typedef int (*var_initializer_t)(variable_t *, size_t);

#endif
