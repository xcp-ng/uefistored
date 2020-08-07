#ifndef __H_STORAGE_
#define __H_STORAGE_

#include <stdint.h>

#include "common.h"

#define MAX_STORAGE_SIZE MB(256)
#define MAX_VARIABLE_SIZE KB(2)

int storage_init(void);
size_t storage_count(void);
void storage_deinit(void);
int storage_get(const UTF16 *name, void *dest, size_t n, size_t *len, uint32_t *attrs);
int storage_set(const UTF16 *name, const void *val, const size_t len, const uint32_t attrs);
void storage_destroy(void);
int storage_next(variable_t *next);
int storage_remove(const UTF16 *name);
int storage_exists(const UTF16 *name);
uint64_t storage_used(void);

#endif