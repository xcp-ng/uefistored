#ifndef __H_RAMDB_
#define __H_RAMDB_

#include <stdint.h>

#include "common.h"

int ramdb_init(void);
void ramdb_deinit(void);
int ramdb_get(const UTF16 *name, void *dest, size_t n, size_t *len, uint32_t *attrs);
int ramdb_set(const UTF16 *name, const void *val, const size_t len, const uint32_t attrs);
void ramdb_destroy(void);
int ramdb_next(variable_t *current, variable_t *next);
int ramdb_exists(const UTF16 *name);
void ramdb_debug(void);

#endif
