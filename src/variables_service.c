#include "storage.h"
#include "common.h"
#include "log.h"
#include "uefi/types.h"
#include "uefi/guids.h"
#include "varnames.h"
#include "variable.h"

bool valid_attrs(uint32_t attrs)
{
    if ( attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS )
        return false;
    else if ( attrs & EFI_VARIABLE_HARDWARE_ERROR_RECORD )
        return false;
    else if ( (attrs & RT_BS_ATTRS) == EFI_VARIABLE_RUNTIME_ACCESS )
        return false;
    else if ( !(attrs & (RT_BS_ATTRS)) )
        return false;

    return true;
}

/**
 * Returns true if variable is read-only, otherwise false.
 */
static bool is_ro(UTF16 *variable)
{
    if ( !variable )
        return false;

    /* TODO: simply save and use the attrs */
    return strcmp16(variable, SECURE_BOOT_NAME) == 0;
}

EFI_STATUS
get_variable(UTF16 *variable, EFI_GUID *guid, uint32_t *attrs, size_t *size, void *data)
{
    
    uint8_t tmp[MAX_VARIABLE_DATA_SIZE] = {0};
    size_t tmpsz;
    uint32_t tmpattrs;
    int ret;

    if ( !variable )
        return EFI_INVALID_PARAMETER;

    ret = storage_get(variable, tmp, MAX_VARIABLE_DATA_SIZE, &tmpsz, &tmpattrs);

    if ( ret == VAR_NOT_FOUND )
        return EFI_NOT_FOUND;
    else if ( ret < 0 )
    {
        return EFI_DEVICE_ERROR;
    }
    else if ( !(tmpattrs & EFI_VARIABLE_RUNTIME_ACCESS) )
    {
        return EFI_NOT_FOUND;
    }
    else if ( tmpsz > *size )
    {
        *size = tmpsz;
        return EFI_BUFFER_TOO_SMALL;
    }
    /*
     * This should NEVER happen.  Indicates a varstored bug.  This means we
     * saved a value into our variables database that is actually larger than
     * the shared memory between varstored and OVMF XenVariable.  XenVariable's
     * SetVariable() should prevent this!
     *
     * TODO: make this more precise.  Subtract size of other serialized fields.
     */
    else if ( tmpsz > MAX_SHARED_OVMF_MEM )
        return EFI_DEVICE_ERROR;

    memcpy(data, tmp, tmpsz);
    *size = tmpsz;
    *attrs = tmpattrs;

    return EFI_SUCCESS;
}

EFI_STATUS set_variable(UTF16 *variable, EFI_GUID *guid, uint32_t attrs, size_t datasz, void *data)
{
    int ret;

    if ( !variable || !guid || !data )
        return -1;

    if ( is_ro(variable) )
        return EFI_WRITE_PROTECTED;

    uc2_ascii_safe(variable, strsize16(variable), strbuf, 512);

    ret = storage_set(variable, data, datasz, attrs);

    if ( ret < 0 )
    {
        ERROR("Failed to set variable %s in db\n", strbuf);
        return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}

EFI_STATUS query_variable_info(uint32_t attrs, 
                               uint64_t *max_variable_storage,
                               uint64_t *remaining_variable_storage,
                               uint64_t *max_variable_size)
{
    if ( !valid_attrs(attrs) )
        return EFI_UNSUPPORTED;

    *max_variable_storage = MAX_STORAGE_SIZE;
    *max_variable_size = MAX_VARIABLE_SIZE;
    *remaining_variable_storage = MAX_STORAGE_SIZE - storage_used();

    return EFI_SUCCESS;
}
