#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include "common.h"
#include "serializer.h"
#include "uefitypes.h"

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
    memcpy (*ptr, &var, sizeof var);
    *ptr += sizeof var;
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

void serialize_guid(uint8_t **ptr, EFI_GUID *Guid)
{
    memcpy (*ptr, Guid, 16);
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
int unserialize_data(uint8_t **ptr, void *buf, size_t buflen)
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

uint64_t unserialize_uintn(uint8_t **ptr)
{
    uint64_t ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

uint32_t unserialize_uint32(uint8_t **ptr)
{
    uint32_t ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

uint64_t unserialize_uint64(uint8_t **ptr)
{
    uint64_t ret;

    memcpy(&ret, *ptr, sizeof ret);
    *ptr += sizeof ret;

    return ret;
}

void unserialize_guid(uint8_t **ptr, EFI_GUID *Guid)
{
    memcpy (Guid, *ptr, 16);
    *ptr += 16;
}

bool unserialize_boolean(uint8_t **ptr)
{
    bool val;

    memcpy(&val, *ptr, sizeof val);
    *ptr += sizeof(val);

    return val;
}

/**
 * Unserialize the name field.
 *
 * Adds a UTF16 null-terminator (i.e, 2 bytes of zero).
 * 
 * Returns -1 if error, otherwise the length of the name 
 * (not including null-terminator).
 */
int unserialize_name(uint8_t **ptr, void *buf, size_t buflen)
{
    size_t len;
    uint8_t *p = buf;

    memcpy(&len, *ptr, sizeof(len));
    *ptr += sizeof(len);

    /* We add buffer of 2 bytes at end for UTF16 null-terminator */
    if ( len + 2 > buflen )
        return -1;

    memcpy(p, *ptr, len);
    p[len] = 0;
    p[len + 1] = 0;

    *ptr += len;
    
    return len;
}

EFI_STATUS unserialize_result(uint8_t **ptr)
{
    EFI_STATUS status;

    memcpy(&status, *ptr, sizeof status);
    *ptr += sizeof(status);

    return status;
}

int serialize_var(uint8_t **p, size_t n, variable_t *var)
{
    size_t used = 0;

    if ( sizeof(var->namesz) > n )
        return -1;

    memcpy(*p, &var->namesz, sizeof(var->namesz)); 
    *p += sizeof(var->namesz);
    used += sizeof(var->namesz);

    if ( var->namesz + used > n )
        return -1;

    memcpy(*p, var->name, var->namesz); 
    *p += var->namesz;
    used += var->namesz;

    if ( sizeof(var->datasz) + used > n )
        return -1;

    memcpy(*p, &var->datasz, sizeof(var->datasz)); 
    *p += sizeof(var->datasz);
    used += sizeof(var->datasz);

    if ( var->datasz + used > n )
        return -1;

    memcpy(*p, var->data, var->datasz); 
    *p += var->datasz;
    used += var->datasz;

    return 0;
}
