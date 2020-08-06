#ifndef __H_RAMDB_
#define __H_RAMDB_

#include <stdint.h>

#include "common.h"

#define MAX_STORAGE_SIZE MB(256)
#define MAX_VARIABLE_SIZE KB(2)

int ramdb_init(void);
size_t ramdb_count(void);
void ramdb_deinit(void);
int ramdb_get(const UTF16 *name, void *dest, size_t n, size_t *len, uint32_t *attrs);
int ramdb_set(const UTF16 *name, const void *val, const size_t len, const uint32_t attrs);
void ramdb_destroy(void);
int ramdb_next(variable_t *next);
int ramdb_remove(const UTF16 *name);
int ramdb_exists(const UTF16 *name);
uint64_t ramdb_used(void);

#endif
