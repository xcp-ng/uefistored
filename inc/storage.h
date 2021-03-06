#ifndef __H_STORAGE_
#define __H_STORAGE_

#include <stdint.h>

#include "variable.h"
#include "config.h"
#include "common.h"
#include "uefi/types.h"

size_t storage_count(void);
EFI_STATUS storage_get(const UTF16 *name, size_t namesz, const EFI_GUID *guid, uint32_t *attrs, void *data, size_t *data_size);
EFI_STATUS storage_set(const UTF16 *name, size_t namesz, const EFI_GUID *guid, const void *val,
                       size_t len, uint32_t attrs);
EFI_STATUS storage_set_with_timestamp(const UTF16 *name, size_t namesz, const EFI_GUID *guid,
        const void *val, size_t len, uint32_t attrs, EFI_TIME
        *timestamp);
void storage_destroy(void);
variable_t *storage_next_variable(UTF16 *name, size_t namesz, EFI_GUID *guid);
bool storage_exists(const UTF16 *name, size_t namesz, const EFI_GUID *guid);
uint64_t storage_used(void);
EFI_STATUS storage_remove(const UTF16 *name, size_t namesz, const EFI_GUID *guid);
EFI_STATUS storage_get_var_ptr(variable_t **var, const UTF16 *name, size_t namesz, const EFI_GUID *guid);
EFI_STATUS storage_iter(variable_t *var);
variable_t *storage_find_variable(const UTF16 *name, size_t namesz, const EFI_GUID *guid);
void storage_print_all(void);
void storage_print_all_data_only(void);

#endif
