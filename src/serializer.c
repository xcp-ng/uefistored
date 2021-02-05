#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include "common.h"
#include "barrier.h"
#include "storage.h"
#include "log.h"
#include "serializer.h"
#include "uefi/types.h"
#include "variable.h"

static const char VARS[] = "VARS";

struct variable_list {
    variable_t *variable;
    struct variable_list *next;
};

#define WRITE_ONCE_CAST(ptr, data) \
    WRITE_ONCE((*(typeof(data)*)ptr), data)

void serialize_name(uint8_t **ptr, const UTF16 *name, size_t namesz)
{
    WRITE_ONCE_CAST(*ptr, namesz);
    *ptr += sizeof namesz;

    barrier();
    __builtin_memcpy(*ptr, name, namesz);
    barrier();

    *ptr += namesz;
}

void serialize_data(uint8_t **ptr, const void *data, uint64_t datasz)
{
    WRITE_ONCE_CAST(*ptr, datasz);
    *ptr += sizeof datasz;

    barrier();
    __builtin_memcpy(*ptr, data, datasz);
    barrier();

    *ptr += datasz;
}

void serialize_uint16(uint8_t **ptr, uint16_t var)
{
    WRITE_ONCE_CAST(*ptr, var);
    *ptr += sizeof(var);
}

void serialize_uint8(uint8_t **ptr, uint8_t var)
{
    WRITE_ONCE_CAST(*ptr, var);
    *ptr += sizeof(var);
}

void serialize_uint64(uint8_t **ptr, uint64_t var)
{
    WRITE_ONCE_CAST(*ptr, var);
    *ptr += sizeof(var);
}

void serialize_uintn(uint8_t **ptr, uint64_t var)
{
    return serialize_uint64(ptr, var);
}

void serialize_uint32(uint8_t **ptr, uint32_t var)
{
    WRITE_ONCE_CAST(*ptr, var);
    *ptr += sizeof var;
}

void serialize_boolean(uint8_t **ptr, bool var)
{
    WRITE_ONCE_CAST(*ptr, var);
    *ptr += sizeof var;
}

void serialize_cert(uint8_t **ptr, const uint8_t cert[SHA256_DIGEST_SIZE])
{
    barrier();
    __builtin_memcpy(*ptr, cert, SHA256_DIGEST_SIZE);
    barrier();

    *ptr += SHA256_DIGEST_SIZE;
}

void serialize_command(uint8_t **ptr, command_t cmd)
{
    serialize_uint32(ptr, (uint32_t)cmd);
}

void serialize_guid(uint8_t **ptr, const EFI_GUID *guid)
{
    barrier();
    __builtin_memcpy(*ptr, guid, 16);
    barrier();

    *ptr += sizeof(*guid);;
}

void serialize_result(uint8_t **ptr, EFI_STATUS status)
{
    barrier();
    __builtin_memcpy(*ptr, &status, sizeof(status));
    barrier();

    *ptr += sizeof(status);
}

/**
 * Unserialize a XenVariable RPC data field
 *
 * Parameters:
 *  @ptr: The start of the data field
 *  @buf: The target buffer to copy the data into
 *  @buflen: The size of the target buffer
 *
 * Returns:
 *    The size of the data field.
 */
uint64_t unserialize_data(const uint8_t **ptr, void *buf, size_t buflen)
{
    uint64_t ret;

    barrier();
    memcpy(&ret, *ptr, sizeof(ret));
    barrier();

    assert(ret < buflen && ret < INT_MAX);

    *ptr += sizeof(ret);

    barrier();
    memcpy(buf, *ptr, ret);
    barrier();

    *ptr += ret;

    return ret;
}

uint8_t unserialize_uint8(const uint8_t **ptr)
{
    uint8_t ret;

    ret = READ_ONCE(**ptr);
    *ptr += sizeof ret;

    return ret;
}

uint16_t unserialize_uint16(const uint8_t **ptr)
{
    uint16_t ret;

    ret = READ_ONCE(**(uint16_t**)ptr);
    *ptr += sizeof ret;

    return ret;
}

uint32_t unserialize_uint32(const uint8_t **ptr)
{
    uint32_t ret;

    ret = READ_ONCE(**(uint32_t**)ptr);
    *ptr += sizeof ret;

    return ret;
}

uint64_t unserialize_uint64(const uint8_t **ptr)
{
    uint64_t ret;

    ret = READ_ONCE(**(uint64_t**)ptr);
    *ptr += sizeof ret;

    return ret;
}

uint64_t unserialize_uintn(const uint8_t **ptr)
{
    return unserialize_uint64(ptr);
}

void unserialize_guid(const uint8_t **ptr, EFI_GUID *guid)
{
    barrier();
    memcpy(guid, *ptr, sizeof(EFI_GUID));
    barrier();

    *ptr += sizeof(EFI_GUID);
}

bool unserialize_boolean(const uint8_t **ptr)
{
    bool ret;

    ret = READ_ONCE(**(const bool**)ptr);
    *ptr += sizeof(ret);

    return ret;
}

uint64_t unserialize_namesz(const uint8_t **ptr)
{
    return unserialize_uint64(ptr);
}

void unserialize_cert(const uint8_t **ptr, uint8_t cert[SHA256_DIGEST_SIZE])
{
    barrier();
    __builtin_memcpy(cert, *ptr, SHA256_DIGEST_SIZE);
    barrier();

    *ptr += SHA256_DIGEST_SIZE;
}

EFI_STATUS unserialize_result(const uint8_t **ptr)
{
    EFI_STATUS status;

    status = READ_ONCE(**(const EFI_STATUS **)ptr);
    *ptr += sizeof(status);

    return status;
}

/* For XAPI, do NOT use for shared memory */
void unserialize_variable_list_header(const uint8_t **ptr,
                                      struct variable_list_header *hdr)
{
    memcpy(hdr, *ptr, sizeof(*hdr));
    *ptr += sizeof(*hdr);
}

/* For XAPI, do NOT use for shared memory */
int unserialize_var_cached(const uint8_t **ptr, variable_t *var)
{
    uint8_t cert[32];
    EFI_TIME timestamp;
    UTF16 name[MAX_VARIABLE_NAME_SIZE] = { 0 };
    EFI_GUID guid;
    uint8_t *data;
    uint64_t namesz, datasz;
    uint32_t attrs;
    int ret;

    if (!ptr || !var)
        return -1;

    namesz = unserialize_uint64(ptr);

    if (namesz == 0 || namesz > MAX_VARIABLE_NAME_SIZE)
        return -1;

    memcpy(name, *ptr, namesz);
    *ptr += namesz;

    datasz = unserialize_uint64(ptr);

    if (datasz == 0)
        return -1;

    data = malloc(datasz);

    if (!data)
        return -1;

    memcpy(data, *ptr, datasz);
    *ptr += datasz;

    unserialize_guid(ptr, &guid);
    attrs = unserialize_uint32(ptr);
    unserialize_timestamp(ptr, &timestamp);
    unserialize_cert(ptr, cert);

    ret = variable_create_noalloc(var, name, namesz, data, datasz, &guid, attrs,
                                  &timestamp, cert);

    free(data);

    return ret;
}

void unserialize_timestamp(const uint8_t **p, EFI_TIME *timestamp)
{
    if (!p || !timestamp)
        return;

    timestamp->Year = unserialize_uint16(p);
    timestamp->Month = unserialize_uint8(p);
    timestamp->Day = unserialize_uint8(p);
    timestamp->Hour = unserialize_uint8(p);
    timestamp->Minute = unserialize_uint8(p);
    timestamp->Second = unserialize_uint8(p);

    /* These should alqays all be zero, but unserialize anyway in
     * case the spec advances and changes */
    timestamp->Pad1 = unserialize_uint8(p);
    timestamp->Nanosecond = unserialize_uint32(p);
    timestamp->TimeZone = unserialize_uint16(p);
    timestamp->Daylight = unserialize_uint8(p);
    timestamp->Pad2 = unserialize_uint8(p);
}

void serialize_timestamp(uint8_t **p, const EFI_TIME *timestamp)
{
    serialize_uint16(p, timestamp->Year);
    serialize_uint8(p, timestamp->Month);
    serialize_uint8(p, timestamp->Day);
    serialize_uint8(p, timestamp->Hour);
    serialize_uint8(p, timestamp->Minute);
    serialize_uint8(p, timestamp->Second);

    /* These should always all be zero, but serialize anyway in
     * case the spec advances and changes */
    serialize_uint8(p, timestamp->Pad1);
    serialize_uint32(p, timestamp->Nanosecond);
    serialize_uint16(p, timestamp->TimeZone);
    serialize_uint8(p, timestamp->Daylight);
    serialize_uint8(p, timestamp->Pad2);
}

/**
 * Serialize a variable into mem pointed to by *p.
 *
 * WARNING: check that *p points to enough memory for var before calling!
 *
 * Returns 0 if success, otherwise -1.
 */
int serialize_var(uint8_t **p, const variable_t *var)
{
    if (!p || !var)
        return -1;

    if (!var->name || !var->data)
        return -1;

    serialize_name(p, var->name, var->namesz);
    serialize_data(p, var->data, var->datasz);
    serialize_guid(p, &var->guid);
    serialize_uint32(p, var->attrs);
    serialize_timestamp(p, &var->timestamp);
    serialize_cert(p, var->cert);

    return 0;
}

static uint64_t payload_size(const variable_t *var, size_t n)
{
    uint64_t sum = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        sum += variable_size(&var[i]);
    }

    return sum;
}

/* For XAPI, do NOT use on shared memory */
static void serialize_variable_list_header(uint8_t **ptr, const variable_t *var,
                                           size_t n)
{
    struct variable_list_header hdr = { 0 };

    memcpy(&hdr.magic, &VARS, sizeof(hdr.magic));
    hdr.version = 1;
    hdr.variable_count = n;
    hdr.payload_size = payload_size(var, n);

    memcpy(*ptr, &hdr, sizeof(hdr));
    *ptr += sizeof(hdr);
}

/**
 * Serialize a variable list.
 *
 * Returns the number of successfully serialized variables, 
 */
int serialize_variable_list(uint8_t **ptr, size_t sz, const variable_t *var,
                            size_t n)
{
    size_t i, sum;

    if (!ptr || !var) {
        ERROR("%s: bad ptr\n", __func__);
        return 0;
    }

    serialize_variable_list_header(ptr, var, n);

    sum = 0;
    for (i = 0; i < n; i++) {
        sum += variable_size(&var[i]);

        if (sum > sz)
            return i;

        if (serialize_var(ptr, &var[i]) < 0)
            return i;
    }

    return 0;
}

/**
 * Unserialize a variable list to memory at *ptr.
 *
 * Returns the number of variables unserializedr.
 */
uint64_t unserialize_variable_list(const uint8_t **ptr)
{
    variable_t *var;
    int ret = 0;
    struct variable_list_header hdr;
    uint64_t i;

    if (!ptr)
        return 0;

    unserialize_variable_list_header(ptr, &hdr);

    for (i = 0; i < hdr.variable_count; i++) {
        var = variable_create_unserialize(ptr);
        ret = storage_set(var->name, var->namesz, &var->guid, var->data,
                          var->datasz, var->attrs);
        variable_destroy(var);

        if (ret < 0)
            return i;
    }

    return i;
}

void free_variable_list_node(struct variable_list *list)
{
    free(list->variable);

    list->variable = NULL;
    list->next = NULL;

    free(list);
}

void free_variable_list(struct variable_list *list)
{
    struct variable_list *cur, *next;

    cur = list;

    while (cur->next) {
        next = cur->next;

        if (cur)
            free_variable_list_node(cur);

        cur = next;
    }

    if (cur)
        free_variable_list_node(cur);
}
