#ifndef __H_COMMON
#define __H_COMMON

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>

#include "uefi/types.h"
#include "variable.h"

#define MAX_SHARED_OVMF_MEM (SHMEM_PAGES * PAGE_SIZE)

#define KB(x) (x * 1024)
#define MB(x) (KB(x) * 1024)

#define VAR_PADDING 48UL
#define UTF16_CHAR_SZ sizeof(UTF16)

#define min(x, y) ((x) < (y) ? (x) : (y))

#define MAX_VAR_COUNT 512

#define VARSTORED_ERROR 1
#define VAR_NOT_FOUND (-10)

#define PAGE_SIZE (4<<10)

#define RT_BS_ATTRS (EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS)

/* OVMF XenVariable loads 16 pages of shared memory to pass varstored the command */
#define SHMEM_PAGES 16
#define SHMEM_SIZE (SHMEM_PAGES * PAGE_SIZE)

void dprint_variable(variable_t *var);

#define USE_STREAM 1

uint64_t strlen16(const UTF16 *str);
uint64_t strsize16(const UTF16 *str);
int strcmp16(const UTF16 *a, const UTF16 *b);
int strncpy16(UTF16 *a, const UTF16 *b, const size_t n);

void uc2_ascii_safe(UTF16 *uc2, size_t uc2_len, char *ascii, size_t len);
void uc2_ascii(UTF16 *uc2, char *ascii, size_t len);

typedef int (*var_initializer_t)(variable_t *, size_t);
variable_t *find_variable(const UTF16 *name, variable_t variables[MAX_VAR_COUNT], size_t n);

#endif
