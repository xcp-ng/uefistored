#ifndef __H_STORAGE_
#define __H_STORAGE_

#include <stdint.h>

#include "variable.h"
#include "config.h"
#include "common.h"
#include "uefi/types.h"

void storage_init(void);
size_t storage_count(void);
void storage_deinit(void);
EFI_STATUS storage_get(const UTF16 *name, const EFI_GUID *guid, uint32_t *attrs, void *data, size_t *data_size);
EFI_STATUS storage_set(const UTF16 *name, const EFI_GUID *guid, const void *val,
                const size_t len, const uint32_t attrs);
EFI_STATUS storage_set_with_timestamp(const UTF16 *name, const EFI_GUID *guid,
        const void *val, const size_t len, const uint32_t attrs, EFI_TIME
        *timestamp);
void storage_destroy(void);
EFI_STATUS storage_next(size_t *namesz, UTF16 *name, EFI_GUID *guid);
variable_t *storage_next_variable(UTF16 *name, EFI_GUID *guid);
EFI_STATUS storage_get_var(variable_t *var, const UTF16 *name, const EFI_GUID *guid);
int storage_exists(const UTF16 *name, const EFI_GUID *guid);
uint64_t storage_used(void);
EFI_STATUS storage_remove(const UTF16 *name, const EFI_GUID *guid);
EFI_STATUS storage_get_var_ptr(variable_t **var, const UTF16 *name, const EFI_GUID *guid);
EFI_STATUS storage_iter(variable_t *var);
variable_t *storage_find_variable(const UTF16 *name, const EFI_GUID *guid);

void _storage_debug(const char *func, int lineno);

#define storage_debug() _storage_debug(__func__, __LINE__)

#endif
