#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "common.h"
#include "log.h"
#include "storage.h"
#include "uefi/types.h"
#include "serializer.h"
#include "variable.h"

int variable_set_attrs(variable_t *var, const uint32_t attrs)
{
    if (!var)
        return -1;

    var->attrs = attrs;

    return 0;
}

int variable_set_data(variable_t *var, const uint8_t *data, uint64_t datasz)
{
    if (!var || !data || datasz == 0)
        return -1;

    if (datasz > MAX_VARIABLE_DATA_SIZE)
        return -2;

    if (var->datasz != datasz) {
        if (var->data) {
            free(var->data);
            var->data = NULL;
        }

        var->data = malloc(datasz);
    }

    var->datasz = datasz;

    memcpy(var->data, data, datasz);

    return 0;
}

int variable_set_guid(variable_t *var, const EFI_GUID *guid)
{
    if (!var || !guid)
        return -1;

    memcpy(&var->guid, guid, sizeof(var->guid));

    return 0;
}

/**
 * Some RCs of uefistored also stored the the null terminator.
 * This was changed for backwards compatibility with
 * varstored.
 */
static inline void sanitize_namesz(variable_t *var)
{
    if (!var)
        return;

    /* Leave out null-terminator if it exists */
    if (var->name[(var->namesz / sizeof(UTF16) - 1)] == 0) {
        var->namesz = var->namesz - sizeof(UTF16);
    }
}

int variable_set_name(variable_t *var, const UTF16 *name, size_t namesz)
{
    if (!var || !name || namesz > MAX_VARIABLE_NAME_SIZE)
        return -EINVAL;

    if (namesz == 0)
        return -1;

    if (namesz > MAX_VARIABLE_NAME_SIZE)
        return -2;

    var->namesz = namesz;
    memcpy(var->name, name, var->namesz);
    sanitize_namesz(var);

    return 0;
}

variable_t *variable_create(const UTF16 *name, size_t namesz,
                            const uint8_t *data, const uint64_t datasz,
                            const EFI_GUID *guid, const uint32_t attrs)
{
    int ret;
    variable_t *var;

    if (!name || !data || !guid || datasz == 0)
        return NULL;

    var = calloc(1, sizeof(variable_t));

    if (!var)
        return NULL;

    ret = variable_set_name(var, name, namesz);

    if (ret < 0) {
        free(var);
        return NULL;
    }

    ret = variable_set_data(var, data, datasz);

    if (ret < 0) {
        free(var);
        return NULL;
    }

    memcpy(&var->guid, guid, sizeof(var->guid));
    var->attrs = attrs;

    return var;
}

/**
 * Returns a variable_t ptr created from a byte serialization.
 *
 * Unlike other unserialize_* functions, the return pointer
 * must be freed by the caller.
 */
variable_t *variable_create_unserialize(const uint8_t **ptr)
{
    variable_t *var;
    int ret;

    var = calloc(1, sizeof(variable_t));

    ret = unserialize_var_cached(ptr, var);

    if (ret < 0)
        return NULL;

    return var;
}

int variable_set_timestamp(variable_t *var, const EFI_TIME *timestamp)
{
    if (!var || !timestamp)
        return -1;

    memcpy(&var->timestamp, timestamp, sizeof(var->timestamp));

    return 0;
}

int variable_set_cert(variable_t *var, const uint8_t *cert)
{
    if (!var || !cert)
        return -1;

    memcpy(var->cert, cert, SHA256_DIGEST_SIZE);

    return 0;
}


int variable_create_noalloc(variable_t *var, const UTF16 *name, size_t namesz,
                            const uint8_t *data, const uint64_t datasz,
                            const EFI_GUID *guid, const uint32_t attrs,
                            const EFI_TIME *timestamp,
                            const uint8_t *cert)
{
    if (!var || !name || !data || !guid || datasz == 0)
        return -1;

    if (variable_set_name(var, name, namesz) < 0)
        return -1;

    if (variable_set_data(var, data, datasz) < 0)
        goto cleanup_name;

    if (variable_set_guid(var, guid) < 0)
        goto cleanup_data;

    if (variable_set_attrs(var, attrs) < 0)
        goto cleanup_data;

    if (timestamp && variable_set_timestamp(var, timestamp) < 0)
        goto cleanup_data;

    if (cert && variable_set_cert(var, cert) < 0)
        goto cleanup_data;

    return 0;

cleanup_data:
    memset(var->data, 0, datasz);

cleanup_name:
    memset(var->name, 0, namesz);
    return -1;
}

void variable_destroy_noalloc(variable_t *var)
{
    if (!var)
        return;

    if (var->name) {
        memset(var->name, 0, MAX_VARIABLE_NAME_SIZE);
        var->namesz = 0;
    }

    if (var->data) {
        free(var->data);
        var->data = NULL;
        var->datasz = 0;
    }

    memset(var, 0, sizeof(*var));
}

void variable_destroy(variable_t *var)
{
    if (!var)
        return;

    variable_destroy_noalloc(var);
    free(var);
}

int variable_copy(variable_t *dst, const variable_t *src)
{
    int ret;

    if (!dst || !src)
        return -1;

    ret = variable_set_name(dst, src->name, src->namesz);

    if (ret < 0) {
        return ret;
    }

    ret = variable_set_data(dst, src->data, src->datasz);

    if (ret < 0) {
        return ret;
    }

    ret = variable_set_guid(dst, &src->guid);

    if (ret < 0) {
        return ret;
    }

    ret = variable_set_attrs(dst, src->attrs);

    if (ret < 0) {
        return ret;
    }

    return 0;
}

bool variable_eq(const variable_t *a, const variable_t *b)
{
    if (!a || !b)
        return false;

    if (a->namesz != b->namesz)
        return false;

    if (a->datasz != b->datasz)
        return false;

    if (memcmp(a->name, b->name, a->namesz) != 0)
        return false;

    if (memcmp(a->data, b->data, a->datasz) != 0)
        return false;

    return true;
}

uint64_t variable_size(const variable_t *var)
{
    uint64_t sum;

    if (!var)
        return 0;

    /* Name Length */
    sum = sizeof(var->namesz);

    /* Name Value */
    sum += variable_serialized_namesz(var);

    /* Data Length */
    sum += sizeof(var->datasz);

    /* Data Value */
    sum += var->datasz;

    /* GUID Value */
    sum += sizeof(var->guid);

    /* ATTRS Value */
    sum += sizeof(var->attrs);

    /* UEFI TimeStamp Value */
    sum += sizeof(var->timestamp);

    /* Cert */
    sum += sizeof(var->cert);

    return sum;
}

/**
 * This function populates an array of variables from byte-serialized form.
 *
 * @parm vars the buffer array of variables
 * @parm n the max size of the array
 * @parm bytes pointer to the array of bytes of serialized variables
 * @parm bytes_sz the size of the array of bytes
 *
 * @return the number of variables on success, otherwise -1.
 */
int from_bytes_to_vars(variable_t *vars, size_t n, const uint8_t *bytes)
{
    int ret;
    const uint8_t *ptr = bytes;
    struct variable_list_header hdr;
    size_t i;

    if (!vars || !bytes)
        return -1;

    unserialize_variable_list_header(&ptr, &hdr);

    if (hdr.variable_count > n)
        return -1;

    for (i = 0; i < hdr.variable_count; i++) {
        ret = unserialize_var_cached(&ptr, &vars[i]);

        if (ret < 0)
            break;
    }

    assert(i <= INT_MAX);

    return (int)i;
}

variable_t *find_variable(const UTF16 *name, size_t namesz,
                          const EFI_GUID *guid, variable_t *variables, size_t n)
{
    variable_t *var;
    size_t i;

    if (!name || !variables || !guid)
        return NULL;

    for (i = 0; i < n; i++) {
        var = &variables[i];

        if (var->namesz != namesz)
            continue;

        if (memcmp((UTF16 *)var->name, name, var->namesz) == 0 &&
            memcmp(guid, &var->guid, sizeof(EFI_GUID)) == 0)
            return var;
    }

    return NULL;
}
