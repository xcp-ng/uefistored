#ifndef __H_STORAGE_
#define __H_STORAGE_

#include <stdint.h>

#include "common.h"
#include "uefi/types.h"

#define MAX_STORAGE_SIZE MB(8)
#define MAX_VARIABLE_SIZE (MAX_STORAGE_SIZE / MAX_VAR_COUNT)

#define MAX_VARIABLE_NAME_SIZE KB(1)
#define MAX_VARIABLE_DATA_SIZE (MAX_VARIABLE_SIZE - MAX_VARIABLE_NAME_SIZE)

#if (MAX_VARIABLE_NAME_SIZE + MAX_VARIABLE_DATA_SIZE) != MAX_VARIABLE_SIZE
#error "Name and data max sizes are misconfigured!"
#endif

void storage_init(void);
size_t storage_count(void);
void storage_deinit(void);
EFI_STATUS storage_get(const UTF16 *name, const EFI_GUID *guid, uint32_t *attrs, void *data, size_t *data_size);
EFI_STATUS storage_set(const UTF16 *name, const EFI_GUID *guid, const void *val,
                const size_t len, const uint32_t attrs);
void storage_destroy(void);
EFI_STATUS storage_next(size_t *namesz, UTF16 *name, EFI_GUID *guid);
EFI_STATUS storage_get_var(variable_t *var, const UTF16 *name, const EFI_GUID *guid);
int storage_exists(const UTF16 *name, const EFI_GUID *guid);
uint64_t storage_used(void);
EFI_STATUS storage_remove(const UTF16 *name, const EFI_GUID *guid);
EFI_STATUS storage_get_var_ptr(variable_t **var, const UTF16 *name, const EFI_GUID *guid);

#endif
