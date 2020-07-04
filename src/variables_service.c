#include "backends/ramdb.h"
#include "common.h"
#include "log.h"
#include "uefitypes.h"
#include "uefi_guids.h"
#include "varnames.h"

#define MAX_SHARED_OVMF_MEM (SHMEM_PAGES * PAGE_SIZE)

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
    
    uint8_t tmp[MAX_VARDATA_SZ] = {0};
    size_t tmpsz;
    uint32_t tmpattrs;
    int ret;

    if ( !variable )
        return EFI_INVALID_PARAMETER;

    ret = ramdb_get(variable, tmp, MAX_VARDATA_SZ, &tmpsz, &tmpattrs);

    if ( !(tmpattrs & EFI_VARIABLE_RUNTIME_ACCESS) || ret == VAR_NOT_FOUND )
    {
        return EFI_NOT_FOUND;
    }
    else if ( tmpsz > *size )
    {
        *size = tmpsz;
        return EFI_BUFFER_TOO_SMALL;
    }
    else if ( ret < 0 )
    {
        return EFI_DEVICE_ERROR;
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

EFI_STATUS set_variable(UTF16 *variable, EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
{
    int ret;

    if ( !variable || !guid || !data )
        return -1;

    if ( is_ro(variable) )
        return EFI_WRITE_PROTECTED;

    uc2_ascii_safe(variable, strsize16(variable), strbuf, 512);

    ret = ramdb_set(variable, data, datalen, attrs);

    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}

EFI_STATUS get_next_variable(uint64_t *current_namesz, UTF16 *current_name, EFI_GUID *current_guid)
{
    variable_t current, next;
    EFI_STATUS status = EFI_SUCCESS;
    int ret;

    if ( !current_namesz || !current_name || !current_guid )
        return EFI_DEVICE_ERROR;

    memcpy(&current.namesz, current_namesz, sizeof(*current_namesz));
    memcpy(&current.name, current_name, *current_namesz);
    memcpy(&current.guid, current_guid, sizeof(EFI_GUID));

    ret = ramdb_next(&current, &next);

    if ( ret == 0 )
    {
        return EFI_NOT_FOUND;
    }
    else if ( ret < 0 )
    {
        return EFI_DEVICE_ERROR;
    }
    else if ( next.namesz > *current_namesz )
    {
        *current_namesz = next.namesz;
        return EFI_BUFFER_TOO_SMALL;
    }

    memcpy(current_namesz, &next.namesz, sizeof(*current_namesz));
    memcpy(current_name, next.name, next.namesz);
    memcpy(current_guid, &next.guid, sizeof(EFI_GUID));

    return status;
}
