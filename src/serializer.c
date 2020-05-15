#include <stdint.h>
#include <stdbool.h>
#include <uchar.h>
#include <string.h>
#include <limits.h>

#include "common.h"
#include "serializer.h"
#include "uefitypes.h"

void serialize_name(uint8_t **ptr, char16_t *VariableName)
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
 * Returns -1 if error, otherwise the length of the name.
 */
int unserialize_name(uint8_t **ptr, void *buf, size_t buflen)
{
    size_t len;

    memcpy(&len, *ptr, sizeof(len));
    *ptr += sizeof(len);

    if ( len > buflen )
    {
        return -1;
    }

    memcpy(buf, *ptr, len);
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

