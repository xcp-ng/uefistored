#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "storage.h"
#include "common.h"
#include "uefi/types.h"
#include "log.h"

#define rt_deny_access(attrs)                                                  \
    (efi_at_runtime && !(attrs & EFI_VARIABLE_RUNTIME_ACCESS))

extern bool efi_at_runtime;

static variable_t variables[MAX_VAR_COUNT];
static size_t total;
static uint64_t used;

static inline bool is_delete(uint32_t attrs, size_t datasz)
{
    return datasz == 0 || attrs == 0;
}

size_t storage_count(void)
{
    return total;
}

void storage_destroy(void)
{
    size_t i;
    variable_t *var;

    total = 0;
    used = 0;

    for_each_variable(variables, var, i)
    {
        variable_destroy_noalloc(var);
    }

    memset(variables, 0, sizeof(variables));
}

bool storage_exists(const UTF16 *name, size_t namesz, const EFI_GUID *guid)
{
    return !!find_variable(name, namesz, guid, variables, MAX_VAR_COUNT);
}

variable_t *storage_find_variable(const UTF16 *name, size_t namesz,
                                  const EFI_GUID *guid)
{
    return find_variable(name, namesz, guid, variables, MAX_VAR_COUNT);
}

EFI_STATUS storage_get(const UTF16 *name, size_t namesz, const EFI_GUID *guid,
                       uint32_t *attrs, void *data, size_t *data_size)
{
    variable_t *var;

    if (!name || !guid || !data_size || !attrs) {
        return EFI_DEVICE_ERROR;
    }

    var = find_variable(name, namesz, guid, variables, MAX_VAR_COUNT);

    if (!var) {
        return EFI_NOT_FOUND;
    }

    if (rt_deny_access(var->attrs)) {
        DBG("Found, but inaccessible at runtime\n");
        return EFI_NOT_FOUND;
    }

    if (*data_size < var->datasz) {
        *data_size = var->datasz;
        return EFI_BUFFER_TOO_SMALL;
    }

    if (*data_size > MAX_SHARED_OVMF_MEM) {
        return EFI_DEVICE_ERROR;
    }

    memcpy(data, var->data, var->datasz);
    *data_size = var->datasz;
    *attrs = var->attrs;

    return EFI_SUCCESS;
}

EFI_STATUS storage_get_var_ptr(variable_t **var, const UTF16 *name,
                               size_t namesz, const EFI_GUID *guid)
{
    if (!var || !name || !guid) {
        return EFI_DEVICE_ERROR;
    }

    *var = find_variable(name, namesz, guid, variables, MAX_VAR_COUNT);

    if (!*var) {
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
}

static size_t storage_iter_index = 0;

EFI_STATUS storage_iter(variable_t *var)
{
    variable_t *p;

    while (storage_iter_index < MAX_VAR_COUNT) {
        p = &variables[storage_iter_index];

        if (!p)
            goto err;

        storage_iter_index++;

        if (!variable_is_valid(p))
            continue;

        if (variable_copy(var, p) < 0)
            goto err;

        break;
    }

    /* Reached all variables */
    if (storage_iter_index >= MAX_VAR_COUNT) {
        storage_iter_index = 0;
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;

err:
    storage_iter_index = 0;
    return EFI_DEVICE_ERROR;
}

EFI_STATUS storage_remove(const UTF16 *name, size_t namesz,
                          const EFI_GUID *guid)
{
    size_t i;
    variable_t *var;

    if (!name || !guid)
        return EFI_DEVICE_ERROR;

    for_each_variable(variables, var, i)
    {
        if (var->namesz != namesz)
            continue;

        if (memcmp(var->name, name, var->namesz) == 0 &&
            memcmp(&var->guid, guid, sizeof(var->guid)) == 0) {
            variable_destroy_noalloc(var);
            used -= (MAX_VARIABLE_NAME_SIZE + MAX_VARIABLE_DATA_SIZE);
            total--;
            return EFI_SUCCESS;
        }
    }

    /* Not found */
    return EFI_NOT_FOUND;
}

EFI_STATUS storage_set(const UTF16 *name, size_t namesz, const EFI_GUID *guid,
                       const void *data, size_t datasz, uint32_t attrs)
{
    bool append;
    size_t i;
    int ret;
    variable_t *var;

    if (!name || !guid)
        return EFI_DEVICE_ERROR;

    if (namesz > MAX_VARIABLE_NAME_SIZE || datasz > MAX_VARIABLE_DATA_SIZE ||
        datasz + namesz + storage_used() > MAX_STORAGE_SIZE)
        return EFI_OUT_OF_RESOURCES;

    /* As specified by the UEFI spec */
    if (datasz == 0 || attrs == 0)
        return storage_remove(name, namesz, guid);

    /* Caller passed in a null pointer as data */
    if (!data)
        return EFI_DEVICE_ERROR;

    append = !!(attrs & EFI_VARIABLE_APPEND_WRITE);
    attrs &= ~EFI_VARIABLE_APPEND_WRITE;

    /* If it already exists, replace it */
    for_each_variable(variables, var, i)
    {
        if (var->namesz != namesz) {
            continue;
        }

        if (memcmp(var->name, name, var->namesz) == 0 &&
            memcmp(&var->guid, guid, sizeof(EFI_GUID)) == 0) {

            if (var->attrs != attrs)
                return EFI_INVALID_PARAMETER;

            ret = variable_set_name(var, name, namesz);

            if (ret == -2)
                return EFI_OUT_OF_RESOURCES;
            else if (ret < 0)
                return EFI_DEVICE_ERROR;

            ret = variable_set_data(var, data, datasz, append);

            if (ret == -2)
                return EFI_OUT_OF_RESOURCES;
            else if (ret < 0)
                return EFI_DEVICE_ERROR;

            memcpy(&var->attrs, &attrs, sizeof(var->attrs));
            return EFI_SUCCESS;
        }
    }

    /* If it is completely new, place it in the first found empty slot */
    for_each_variable(variables, var, i)
    {
        if (var->name[0] == 0) {
            ret = variable_create_noalloc(var, name, namesz, data, datasz, guid,
                                          attrs, NULL, NULL);

            if (ret < 0)
                return EFI_DEVICE_ERROR;

            total++;
            used += MAX_VARIABLE_NAME_SIZE + MAX_VARIABLE_DATA_SIZE;
            return EFI_SUCCESS;
        }
    }

    return EFI_DEVICE_ERROR;
}

EFI_STATUS storage_set_with_timestamp(const UTF16 *name, size_t namesz,
                                      const EFI_GUID *guid, const void *data,
                                      size_t datasz, uint32_t attrs,
                                      EFI_TIME *timestamp)
{
    EFI_STATUS status;
    variable_t *var;

    if (!name || !data || !guid || !timestamp)
        return EFI_DEVICE_ERROR;

    status = storage_set(name, namesz, guid, data, datasz, attrs);

    /* If this variable was deleted, then we are done */
    if (is_delete(attrs, datasz))
        return status;

    /* Set the timestamp */
    status = storage_get_var_ptr(&var, name, namesz, guid);

    if (status != EFI_SUCCESS)
        return status;

    if (variable_set_timestamp(var, timestamp) < 0)
        return EFI_DEVICE_ERROR;

    return EFI_SUCCESS;
}

uint64_t storage_used(void)
{
    return used;
}

static variable_t *storage_get_first(void)
{
    int i;

    if (total == 0)
        return NULL;

    /* Find the first variable */
    for (i = 0; i < MAX_VAR_COUNT; i++) {
        if (variable_is_valid(&variables[i]) &&
            !rt_deny_access(variables[i].attrs)) {
            break;
        }
    }

    if (i >= MAX_VAR_COUNT)
        return NULL;

    return &variables[i];
}

variable_t *storage_next_variable(UTF16 *name, size_t namesz, EFI_GUID *guid)
{
    size_t i;
    const variable_t *var;

    if (name[0] == 0 || namesz == 0) {
        return storage_get_first();
    }

    /* Find the previous variable (passed in from caller) */
    for (i = 0; i < MAX_VAR_COUNT; i++) {
        var = &variables[i];

        if (var->namesz != namesz)
            continue;

        if (memcmp(var->name, name, var->namesz) == 0 &&
            memcmp(guid, &var->guid, sizeof(EFI_GUID)) == 0) {
            break;
        }
    }

    /* Go to the next variable, the one we want to return! */
    i++;

    /* Find the next variable */
    for (; i < MAX_VAR_COUNT; i++) {
        if (variable_is_valid(&variables[i]) &&
            !rt_deny_access(variables[i].attrs)) {
            break;
        }
    }

    /* If we are at the end of the array, return NULL */
    if (i >= MAX_VAR_COUNT)
        return NULL;

    return &variables[i];
}

void storage_print_all(void)
{
    size_t i;
    variable_t *var;

    DBG("All UEFI Variables:\n");
    for_each_variable(variables, var, i)
    {
        DPRINTF("%lu: ", i);
        dprint_variable(var);
    }
    DPRINTF("\n");
}
