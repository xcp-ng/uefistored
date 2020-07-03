#include "common.h"
#include "log.h"
#include "uefitypes.h"
#include "varnames.h"

static EFI_STATUS enroll_pk(EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
{
    X509 *cert;
    int ret;

    cert = x509_cert(data, datalen, false, NULL);

    if ( !cert ) 
        return EFI_SECURITY_VIOLATION;

    if ( pk_pubkey )
    {
        ERROR("BUG: enrolling pk, but pk_pubkey already exists!\n");
        return EFI_DEVICE_ERROR;
    }

    pk_pubkey = X509_get_pubkey(cert);

    if ( !pk_pubkey )
    {
        ERROR("failed to extract and alloc PK keypair!\n");
        return EFI_DEVICE_ERROR;
    }

    ret = ramdb_set(PK_NAME, data, datalen, attrs);

    /* If it was successful, then try seting SETUP_MODE_NAME to 0 */
    if ( !ret )
        return set_setup_mode(0);

    return EFI_DEVICE_ERROR;
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

/**
 * Handle the special case of setting the PK.
 */
static EFI_STATUS handle_set_pk(EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
{
    if ( !guid || !data )
        return EFI_DEVICE_ERROR;

    __log_data((uint8_t*)data, datalen);

    if ( ramdb_exists(PK_NAME) == VAR_NOT_FOUND )
        return enroll_pk(guid, attrs, datalen, data);

    if ( !pk_pubkey )
    {
        ERROR("BUG: PK variable exists, but varstored-ng has no key pair for PK saved\n");
        return EFI_DEVICE_ERROR;
    }

    /* Unimplemented */
    return EFI_DEVICE_ERROR; //ProcessVarWithPk(PK_NAME, guid, data, datalen, attrs, true);
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

    //ramdb_debug();

    if ( !(tmpattrs & EFI_VARIABLE_RUNTIME_ACCESS) || ret == VAR_NOT_FOUND )
    {
        DEBUG("tmpattrs=0x%02x, ret=%d\n", tmpattrs, ret);
        return EFI_NOT_FOUND;
    }
    else if ( tmpsz > *size )
    {
        DEBUG("%s: EFI_BUFFER_TOO_SMALL: tmpsz=%lu, *size=%lu\n", __func__, tmpsz, *size);
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

EFI_STATUS
set_variable(UTF16 *variable, EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
{
    int ret;

    if ( !variable || !guid || !data )
        return -1;

    if ( is_ro(variable) )
        return EFI_WRITE_PROTECTED;

    if ( strcmp16(variable, PK_NAME) == 0 )
        return handle_set_pk(guid, attrs, datalen, data);

    DEBUG("TEST!: datalen=%lu\n", datalen);
    uc2_ascii_safe(variable, strsize16(variable), strbuf, 512);
    DPRINTF("TEST: variable=%s\n", strbuf);

    ret = ramdb_set(variable, data, datalen, attrs);

    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}
