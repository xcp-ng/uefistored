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

extern bool efi_at_runtime;

static variable_t variables[MAX_VAR_COUNT];
static size_t total = 0;
static uint64_t used = 0;

void storage_init(void)
{
    storage_destroy();
}

size_t storage_count(void)
{
    return total;
}

void storage_deinit(void)
{
    storage_destroy();
}

void storage_destroy(void)
{
    variable_t *var;

    total = 0;
    used = 0;

    for_each_variable(variables, var)
    {
        variable_destroy_noalloc(var);
    }

    memset(variables, 0, sizeof(variables));
}

int storage_exists(const UTF16 *name, const EFI_GUID *guid)
{
    variable_t *var = NULL;

    var = find_variable(name, guid, variables, MAX_VAR_COUNT);

    if (!var)
        return VAR_NOT_FOUND;

    return 0;
}

EFI_STATUS storage_get(const UTF16 *name, const EFI_GUID *guid, uint32_t *attrs,
                       void *data, size_t *data_size)
{
    variable_t *var;

    if (!name || !guid || !data_size || !attrs) {
        return EFI_DEVICE_ERROR;
    }

    var = find_variable(name, guid, variables, MAX_VAR_COUNT);

    if (!var) {
        DEBUG("find_variable() == NULL\n");
        return EFI_NOT_FOUND;
    }

    if (*data_size < var->datasz) {
        *data_size = var->datasz;
        return EFI_BUFFER_TOO_SMALL;
    }

    if (*data_size > MAX_SHARED_OVMF_MEM) {
        return EFI_DEVICE_ERROR;
    }

    if (efi_at_runtime && !(var->attrs & EFI_VARIABLE_RUNTIME_ACCESS)) {
        DEBUG("Found, but inaccessible at runtime\n");
        return EFI_NOT_FOUND;
    }

    memcpy(data, var->data, var->datasz);
    *data_size = var->datasz;
    *attrs = var->attrs;

    return EFI_SUCCESS;
}

EFI_STATUS storage_get_var_ptr(variable_t **var, const UTF16 *name, const EFI_GUID *guid)
{
    if (!var || !name || !guid) {
        return EFI_DEVICE_ERROR;
    }

    *var = find_variable(name, guid, variables, MAX_VAR_COUNT);

    if (!*var) {
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
}

EFI_STATUS storage_get_var(variable_t *var, const UTF16 *name, const EFI_GUID *guid)
{
    EFI_STATUS status = EFI_SUCCESS;
    int ret;
    uint8_t *data;

    if (!var || !name || !guid)
        return EFI_INVALID_PARAMETER;

    ret = variable_set_name(var, name);

    if (ret < 0) {
        status = EFI_DEVICE_ERROR;
        goto err;
    }

    if (variable_set_guid(var, guid) < 0) {
        status = EFI_DEVICE_ERROR;
        goto err;
    }

    data = malloc(MAX_VARIABLE_DATA_SIZE);

    if (!data) {
        status = EFI_DEVICE_ERROR;
        goto err;
    }

    ret = variable_set_data(var, data, MAX_VARIABLE_DATA_SIZE);

    if (ret < 0)
    {
        status = EFI_DEVICE_ERROR;
        goto err2;
    }

    status = storage_get(var->name, &var->guid, &var->attrs, var->data, &var->datasz);

    if (status != EFI_SUCCESS)
        goto err2;

    return status;

err2:
    free(data);

err:
    variable_destroy_noalloc(var);
    return status;

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

        if (variable_copy(var, p) < 0 )
            goto err;

        break;
    }

    /* Reached all variables */
    if (storage_iter_index >= MAX_VAR_COUNT)
    {
        storage_iter_index = 0;
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;

err:
    storage_iter_index = 0;
    return EFI_DEVICE_ERROR;
}

EFI_STATUS storage_remove(const UTF16 *name, const EFI_GUID *guid)
{
    size_t namesz;
    variable_t *var;

    if (!name || !guid)
        return EFI_DEVICE_ERROR;

    namesz = strsize16(name);

    for_each_variable(variables, var)
    {
        if (var->namesz != namesz)
            continue;

        if (strcmp16(var->name, name) == 0 &&
                memcmp(&var->guid, guid, sizeof(var->guid)) == 0) {
            variable_destroy_noalloc(var);
            used -= (var->datasz + namesz);
            total--;
            return EFI_SUCCESS;
        }
    }

    /* Not found */
    return EFI_NOT_FOUND;
}

EFI_STATUS storage_set(const UTF16 *name, const EFI_GUID *guid, const void *data,
                const size_t datasz, const uint32_t attrs)
{
    int ret;
    size_t namesz;
    variable_t *var;

    if (!name || !data || !guid)
        return EFI_DEVICE_ERROR;

    namesz = strsize16(name);

    if (namesz > MAX_VARIABLE_NAME_SIZE ||
        datasz > MAX_VARIABLE_DATA_SIZE ||
        datasz + namesz + storage_used() > MAX_STORAGE_SIZE)
        return EFI_OUT_OF_RESOURCES;

    /* As specified by the UEFI spec */
    if (datasz == 0 || attrs == 0)
        return storage_remove(name, guid);

    /* If it already exists, replace it */
    for_each_variable(variables, var)
    {
        if (var->namesz != namesz)
            continue;

        if (strcmp16(var->name, name) == 0 && memcmp(&var->guid, guid, sizeof(EFI_GUID)) == 0) {

            /* If the attrs are different, then return EFI_UNSUPPORTED */
            if (var->attrs != attrs)
                return EFI_INVALID_PARAMETER;

            ret = variable_set_name(var, name);

            if (ret == -2)
                return EFI_OUT_OF_RESOURCES;
            else if (ret < 0)
                return EFI_DEVICE_ERROR;

            ret = variable_set_data(var, data, datasz);

            if (ret == -2)
                return EFI_OUT_OF_RESOURCES;
            else if (ret < 0)
                return EFI_DEVICE_ERROR;

            memcpy(&var->attrs, &attrs, sizeof(var->attrs));
            return EFI_SUCCESS;
        }
    }

    /* If it is completely new, place it in the first found empty slot */
    for_each_variable(variables, var)
    {
        if (var->name == NULL) {
            ret = variable_create_noalloc(var, name, data, datasz, guid, attrs);

            if (ret < 0)
                return EFI_DEVICE_ERROR;

            total++;
            used += datasz + namesz;
            return EFI_SUCCESS;
        }
    }

    return EFI_DEVICE_ERROR;
}

uint64_t storage_used(void)
{
    return used;
}

/**
 * Get the next variable in the DB
 *
 * @parm namesz On input, the previous variable name size.  On output, the next
 * variable name size.
 * @parm name On input, the previous variable name. On output, the next
 * variable name.
 * @parm guid On input, the previous variable guid.  On output, the next
 * variable guid.
 *
 * @return EFI_SUCCESS when the next variable has been found
 * @return EFI_DEVICE_ERROR on uefistored bug
 * @return EFI_NOT_FOUND when end of variable array is reached
 * @return EFI_BUFFER_TOO_SMALL if the name buffer is too
 * small for the next variable name.
 */
EFI_STATUS storage_next(size_t *namesz, UTF16 *name, EFI_GUID *guid)
{
    size_t i;
    size_t prev_sz;
    variable_t *var;

    if (!namesz || !name || !guid)
        return EFI_DEVICE_ERROR;

    if (total == 0)
        return EFI_NOT_FOUND;

    if (name[0] == 0 && total > 0) {
        var = &variables[0];
        goto found;
    }

    prev_sz = strsize16(name);

    /* Find the previous variable (passed in from caller) */
    for (i=0; i<MAX_VAR_COUNT; i++) {
        var = &variables[i];

        if (var->namesz != prev_sz)
            continue;

        if (strcmp16(var->name, name) == 0 &&
                memcmp(guid, &var->guid, sizeof(EFI_GUID)) == 0) {
            break;
        }
    }

    /* Go to the next variable, the one we want to return! */
    i++;

    /* Find the next variable */
    for (; i<MAX_VAR_COUNT; i++) {
        if (variable_is_valid(&variables[i]))
            break;
    }

    /* If we are at the end of the array, return EFI_NOT_FOUND */
    if (i >= MAX_VAR_COUNT)
        return EFI_NOT_FOUND;

    var = &variables[i];

found:
    /* Should never happen! */
    if (!var) {
        ERROR("storage_next variable is null, EFI_DEVICE_ERROR\n");
        return EFI_DEVICE_ERROR;
    }

    /*
     * If the caller didn't provide a large enough buffer, return
     * EFI_BUFFER_TOO_SMALL
     */
    if (var->namesz > *namesz)
    {
        *namesz = var->namesz;
        return EFI_BUFFER_TOO_SMALL;
    }

    *namesz = var->namesz;
    memcpy(name, var->name, var->namesz);
    memcpy(guid, &var->guid, sizeof(*guid));

    return EFI_SUCCESS;
}
