#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include "common.h"
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

void serialize_name(uint8_t **ptr, UTF16 *VariableName)
{
    uint64_t VarNameSize = strsize16(VariableName);

    memcpy (*ptr, &VarNameSize, sizeof VarNameSize);
    *ptr += sizeof VarNameSize;
    memcpy (*ptr, VariableName, VarNameSize);
    *ptr += VarNameSize;
}

void serialize_data(uint8_t **ptr, void *Data, uint64_t DataSize)
{
    memcpy (*ptr, &DataSize, sizeof DataSize);
    *ptr += sizeof DataSize;
    memcpy (*ptr, Data, DataSize);
    *ptr += DataSize;
}

void serialize_uintn(uint8_t **ptr, uint64_t var)
{
    memcpy(*ptr, &var, sizeof(var));
    *ptr += sizeof(var);
}

void serialize_uint32(uint8_t **ptr, uint32_t var)
{
    memcpy (*ptr, &var, sizeof var);
    *ptr += sizeof var;
}

void serialize_boolean(uint8_t **ptr, bool var)
{
    memcpy (*ptr, &var, sizeof var);
    *ptr += sizeof var;
}

void serialize_command(uint8_t **ptr, command_t cmd)
{
    serialize_uint32(ptr, (uint32_t)cmd);
}

void serialize_guid(uint8_t **ptr, EFI_GUID *guid)
{
    memcpy (*ptr, guid, 16);
    *ptr += 16;
}

void serialize_result(uint8_t **ptr, EFI_STATUS status)
{
    memcpy(*ptr, &status, sizeof(status));
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
int unserialize_data(const uint8_t **ptr, void *buf, size_t buflen)
{
    uint64_t ret;

    memcpy(&ret, *ptr, sizeof(ret));
    *ptr += sizeof(ret);

    if ( ret > buflen || ret > INT_MAX )
        return -1;

    memcpy(buf, *ptr, ret);
    *ptr += ret;

    return (int)ret;
}

uint32_t unserialize_uint32(const uint8_t **ptr)
{
    uint32_t ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

uint64_t unserialize_uint64(const uint8_t **ptr)
{
    uint64_t ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

uint64_t unserialize_uintn(const uint8_t **ptr)
{
    return unserialize_uint64(ptr);
}

void unserialize_guid(const uint8_t **ptr, EFI_GUID *guid)
{
    memcpy(guid, *ptr, sizeof(EFI_GUID));
    *ptr += sizeof(EFI_GUID);
}

bool unserialize_boolean(const uint8_t **ptr)
{
    bool val;

    memcpy(&val, *ptr, sizeof val);
    *ptr += sizeof(val);

    return val;
}

uint64_t unserialize_namesz(const uint8_t **ptr)
{
    return unserialize_uint64(ptr);
}

/**
 * Unserialize the name field.
 *
 * Adds a UTF16 null-terminator (i.e, 2 bytes of zero).
 * 
 * Returns -1 if error, otherwise the length of the name 
 * (not including null-terminator).
 */
int unserialize_name(const uint8_t **ptr, size_t buf_sz, void *name, size_t n)
{
    uint64_t namesz = n - sizeof(UTF16);

    if ( namesz > buf_sz || namesz > MAX_VARIABLE_NAME_SIZE )
        return -1;

    memcpy(name, *ptr, namesz);
    memset(name + namesz, 0, sizeof(UTF16));

    *ptr += namesz;

    return namesz;
}

EFI_STATUS unserialize_result(const uint8_t **ptr)
{
    EFI_STATUS status;

    memcpy(&status, *ptr, sizeof status);
    *ptr += sizeof(status);

    return status;
}

void unserialize_variable_list_header(const uint8_t **ptr, struct variable_list_header *hdr)
{
    memcpy(hdr, *ptr, sizeof(*hdr));
	*ptr += sizeof(*hdr);
}

int unserialize_var_cached(const uint8_t **ptr, variable_t *var)
{
    UTF16 name[MAX_VARIABLE_NAME_SIZE] = {0};
    EFI_GUID guid;
    uint8_t *data;
    uint64_t namesz, datasz;
    uint32_t attrs;
    int ret;

	if ( !ptr || !var )
		return -1;

    namesz = unserialize_uint64(ptr);

	if ( namesz == 0 || namesz > MAX_VARIABLE_NAME_SIZE )
        return -1;


	memcpy(name, *ptr, namesz);
	*ptr += namesz;

    datasz = unserialize_uint64(ptr);

	if ( datasz == 0 )
		return -1;

	data = malloc(datasz);

    if ( !data )
        return -1;

    memcpy(data, *ptr, datasz);
    *ptr += datasz;

    unserialize_guid(ptr, &guid);
    attrs = unserialize_uint32(ptr);
    *ptr += VAR_PADDING;

    ret = variable_create_noalloc(var, name, data, datasz, &guid, attrs);

    free(data);

    return ret;
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
    if ( !p || !var )
        return -1;

    if ( !var->name || !var->data )
        return -1;

    serialize_value(p, var->namesz);

    memcpy(*p, var->name, var->namesz); 
    *p += var->namesz;

    serialize_value(p, var->datasz);

    memcpy(*p, var->data, var->datasz); 
    *p += var->datasz;

    serialize_value(p, var->guid);
    serialize_value(p, var->attrs);

    return 0;
}

static uint64_t payload_size(const variable_t *var, size_t n)
{
    uint64_t sum = 0;
    size_t i;
    
    for ( i=0; i<n; i++ )
    {
        sum += variable_size(&var[i]);

        /* Pad w/ 48 bytes  -- require by XenServer's varstored */
        sum += VAR_PADDING;
    }

    return sum;
}

static void serialize_variable_list_header(uint8_t **ptr, const variable_t *var, size_t n)
{
    struct variable_list_header hdr = {0};

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
int serialize_variable_list(uint8_t **ptr, size_t sz, const variable_t *var, size_t n)
{
    size_t i, sum;

    if ( !ptr || !var )
    {
        ERROR("%s: bad ptr\n", __func__);
        return 0;
    }

    serialize_variable_list_header(ptr, var, n);

    sum = 0;
    for ( i=0; i<n; i++ )
    {
        sum += variable_size(&var[i]) + VAR_PADDING;

        if ( sum > sz )
            return i;

        if ( serialize_var(ptr, &var[i]) < 0 )
            return i;

        *ptr += VAR_PADDING;
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

    if ( !ptr )
        return 0;

    unserialize_variable_list_header(ptr, &hdr);

    for ( i=0; i<hdr.variable_count; i++ )
    {
        var = variable_create_unserialize(ptr);
        ret = storage_set(var->name, var->data, var->datasz, var->attrs);
        variable_destroy(var);

        if ( ret < 0 )
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

    while ( cur->next )
    {
        next = cur->next;

        if ( cur )
            free_variable_list_node(cur);

        cur = next;
    }

    if ( cur )
        free_variable_list_node(cur);
}
