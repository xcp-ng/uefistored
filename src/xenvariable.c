#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

#include "backends/ramdb.h"
#include "xenvariable.h"
#include "serializer.h"
#include "UefiMultiPhase.h"
#include "uefitypes.h"
#include "uefi_guids.h"
#include "varnames.h"
#include "common.h"
#include "auth_service.h"

static EVP_PKEY *pk_pubkey;

#define _ADDR(x) ((uint64_t)x)

//#define VALIDATE_WRITES


#define MAX_SHARED_OVMF_MEM (SHMEM_PAGES * PAGE_SIZE)

static int set_setup_mode(uint8_t val)
{

    int ret = ramdb_set(
                   SETUP_MODE_NAME,
                   &val,
                   sizeof(val),
                   EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);
    if ( ret < 0 )
        ERROR("%s:%d: Failed to set SETUP_MODE_NAME to %u!\n", __func__, __LINE__, val);

    return ret;
}

static int set_secure_boot(uint8_t val)
{
    int ret;

    ret = ramdb_set(SECURE_BOOT_NAME,
                   &val,
                   sizeof(val),
                   EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);

    if ( ret < 0 )
        ERROR("%s:%d: Failed to set SECURE_BOOT_NAME to %u!\n", __func__, __LINE__, val);

    return ret;
}

static void dprint_attrs(uint32_t attr)
{
    DPRINTF("0x%x:", attr);
    if ( attr & EFI_VARIABLE_NON_VOLATILE )
        DPRINTF("EFI_VARIABLE_NON_VOLATILE,");
    if ( attr & EFI_VARIABLE_BOOTSERVICE_ACCESS )
        DPRINTF("EFI_VARIABLE_BOOTSERVICE_ACCESS,");
    if ( attr & EFI_VARIABLE_RUNTIME_ACCESS )
        DPRINTF("EFI_VARIABLE_RUNTIME_ACCESS,");
    if ( attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD )
        DPRINTF("EFI_VARIABLE_HARDWARE_ERROR_RECORD,");
    if ( attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS )
        DPRINTF("EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,");
    if ( attr & EFI_VARIABLE_APPEND_WRITE )
        DPRINTF("EFI_VARIABLE_APPEND_WRITE,");
    if ( attr & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS )
        DPRINTF("EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,");
}

static void next_var_not_found(void *comm_buf)
{
    uint8_t *ptr;

    DEBUG("GetNextVariableName(): next var not found\n");
    ptr = comm_buf;
    serialize_result(&ptr, EFI_NOT_FOUND);
}

static void device_error(void *comm_buf)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_DEVICE_ERROR);
}

static void buffer_too_small(void *comm_buf, size_t bufsz, size_t namesz)
{
    uint8_t *ptr = comm_buf;
    WARNING("EFI_BUFFER_TOO_SMALL, given bufsz: %lu, requires bufsz: %lu\n", bufsz, namesz);

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)namesz);
}

static void dprint_next_var(variable_t *curr, variable_t *next)
{
    DPRINTF("DEBUG: cmd:GET_NEXT_VARIABLE: curr=");

    if ( curr && curr->namesz > 0 )
    {
        uc2_ascii_safe(curr->name, curr->namesz, strbuf, 512);
        DPRINTF("%s", strbuf);
    }

    DPRINTF(", next=");
    if ( next && next->namesz > 0 )
    {
        uc2_ascii_safe(next->name, next->namesz, strbuf, 512);
        DPRINTF("%s", strbuf);
    }
    DPRINTF("\n");
}

void print_uc2(const char *TAG, void *vn)
{
#if 1
    uc2_ascii(vn, strbuf, 512);
    DEBUG("%s:%s\n", TAG, strbuf);
    memset(strbuf, '\0', 512);
#endif
}

static bool isnull(void *mem, size_t len)
{
    uint8_t *p = mem;

    while ( len-- > 0 )
        if ( *(p++) != 0 )
            return false;

    return true;
}

#ifdef VALIDATE_WRITES
static void validate(void *variable_name, size_t len, void *data, size_t datalen, uint32_t attrs)
{
    int ret;
    uint8_t test_data[MAX_VARDATA_SZ];
    uint32_t test_attrs = 0;
    size_t test_datalen;

    (void) len;

    ret = ramdb_get(variable_name, test_data, MAX_VARDATA_SZ, &test_datalen, &test_attrs);
    if ( ret != 0 )
    {
        ERROR("Failed to validate variable!\n");
        return;
    }

    if ( memcmp(test_data, data, datalen) )
        ERROR("Variable does not match!\n");
    else
        INFO("Variables match!\n");

    if ( attrs != test_attrs )
        ERROR("Attrs does not match!\n");
    else
        INFO("Attrs match!\n");

    dprint_vname("Validate: %s\n", variable_name);
    DPRINTF("FROM DB: ");
    dprint_data(test_data, test_datalen);
    DPRINTF("FROM OVMF: ");
    dprint_data(data, datalen);
    DEBUG("*************************\n");
}
#else
#define validate(...) do { } while ( 0 )
#endif

EFI_STATUS get_variable(UTF16 *variable,
                        EFI_GUID *guid,
                        uint32_t *attrs,
                        size_t *size,
                        void *data)
{
    
    uint8_t tmp[MAX_VARDATA_SZ] = {0};
    size_t tmpsz;
    uint32_t tmpattrs;
    int ret;

    if ( !variable )
        return EFI_INVALID_PARAMETER;

    ret = ramdb_get(variable, tmp, MAX_VARDATA_SZ, &tmpsz, &tmpattrs);

    DEBUG("tmpsz=%lx, size=%lx\n", tmpsz, *size);

    ramdb_debug();

    if ( !(tmpattrs & EFI_VARIABLE_RUNTIME_ACCESS) )
        return EFI_NOT_FOUND;
    else if ( tmpsz > *size )
        return EFI_BUFFER_TOO_SMALL;
    else if ( ret == VAR_NOT_FOUND )
        return EFI_NOT_FOUND;
    else if ( ret < 0 )
        return EFI_DEVICE_ERROR;
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

static void handle_get_variable(void *comm_buf)
{
    size_t len;
    EFI_GUID guid;
    uint32_t attrs, version;
    uint64_t buflen;
    uint8_t data[MAX_VARDATA_SZ];
    UTF16 variable_name[MAX_VARNAME_SZ];
    EFI_STATUS status;
    uint8_t *ptr;

    ptr = comm_buf;
    version = unserialize_uint32(&ptr);
    if ( version != 1 )
    {
        ERROR("Unsupported version of XenVariable RPC protocol\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if ( unserialize_uint32(&ptr) != COMMAND_GET_VARIABLE )
    {
        ERROR("BUG in varstored, wrong command\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    len = unserialize_name(&ptr, variable_name, MAX_VARNAME_SZ);
    if ( len == 0 )
    {
        ERROR("cmd:GET_VARIABLE: UEFI Error: variable name len is 0\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    if ( isnull(variable_name, len) )
    {
        /*
         * This case is not in the UEFI specification.  It seems that this
         * would not be allowed, so we disallow it. 
         */
        DEBUG("cmd:GET_VARIABLE: UEFI Error, variable name is NULL\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    unserialize_guid(&ptr, &guid);

    buflen = unserialize_uint64(&ptr);

    status = get_variable(variable_name, &guid, &attrs, &buflen, data);

    if ( status )
    {
        ptr = comm_buf;
        dprint_vname("cmd:GET_VARIABLE: %s, ", variable_name);
        DPRINTF("error=%lu\n", status);
        serialize_result(&ptr, status);
        return;
    }

    dprint_vname("cmd:GET_VARIABLE: %s\n", variable_name);

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint32(&ptr, attrs);
    serialize_data(&ptr, data, buflen);
}

static void print_set_var(UTF16 *variable_name, size_t len, uint32_t attrs)
{
    dprint_vname("cmd:SET_VARIABLE: %s, attrs=", variable_name);
    dprint_attrs(attrs);
    DPRINTF("\n");
}

static void handle_set_variable(void *comm_buf)
{
    uint8_t *ptr;
    EFI_GUID guid;
    size_t len, datalen;
    UTF16 variable_name[MAX_VARNAME_SZ];
    uint8_t data[MAX_VARDATA_SZ];
    void *dp = data;
    uint32_t attrs, command, version;
    EFI_STATUS status;

    ptr = comm_buf;
    version = unserialize_uint32(&ptr);

    if ( version != 1 )
    {
        ERROR("Invalid XenVariable OVMF module version number: %d, only supports version 1\n",
              version);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    command = unserialize_uint32(&ptr);
    if ( command != COMMAND_SET_VARIABLE )
    {
        ERROR("BUG: varstored accidentally passed a non SET_VARIABLE buffer to the"
              "%s function!, returning EFI_DEVICE_ERROR\n", __func__);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    len = unserialize_name(&ptr, variable_name, MAX_VARNAME_SZ);
    if ( len <= 0 )
    {
        ERROR("%s: len == %lu\n", __func__, len);
        return;
    }

    unserialize_guid(&ptr, &guid);
    datalen = unserialize_data(&ptr, dp, MAX_VARDATA_SZ);
    attrs = unserialize_uint32(&ptr);

    print_set_var(variable_name, len, attrs);

    if ( datalen == 0 )
    {
        ERROR("UEFI error: datalen == 0\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_SECURITY_VIOLATION);
        return;
    }

#if 0
    if (name_eq(variable_name, len, "XV_DEBUG_UINTN"))
    {
        DEBUG("XV_DEBUG_UINTN: 0x%lx\n",  *((uint64_t*)data));
        return;
    }
    else if (name_eq(variable_name, len, "XV_DEBUG_UINT32"))
    {
        DEBUG("XV_DEBUG_UINT32: 0x%x\n",  *((uint32_t*)data));
        return;
    }
    else if (name_eq(variable_name, len, "XV_DEBUG_UINT64"))
    {
        DEBUG("XV_DEBUG_UINT64: 0x%lx\n",  *((uint64_t*)data));
        return;
    }
    else if (name_eq(variable_name, len, "XV_DEBUG_UINT8"))
    {
        DEBUG("XV_DEBUG_UINT8: 0x%x\n",  *((uint8_t*)data));
        return;
    }
    else if (name_eq(variable_name, len, "XV_DEBUG_STR"))
    {
        print_uc2("XV_DEBUG_STR:", data);
        return;
    }
#endif

    status = set_variable(variable_name, &guid, attrs, datalen, dp);

    validate(variable_name, len, dp, datalen, attrs);

    ptr = comm_buf;
    serialize_result(&ptr, status);
}

static inline EFI_SIGNATURE_DATA *pkcert_list_data(EFI_SIGNATURE_LIST *pkcert_list)
{
    return (EFI_SIGNATURE_DATA *)
        (_ADDR(pkcert_list) + sizeof(EFI_SIGNATURE_LIST) + pkcert_list->SignatureHeaderSize);
}

int to_signature_data(uint8_t **signature_data, uint64_t *signature_len, void *data, size_t sz)
{
    EFI_SIGNATURE_LIST *pkcert_list;
    EFI_SIGNATURE_DATA *pkcert_data;
    EFI_VARIABLE_AUTHENTICATION_2 *descriptor;
    size_t descriptor_sz;

    if ( !data )
        return -1;

    descriptor = data;

    if ( OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) +
         OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertType) +
         sizeof(EFI_GUID) >= sz )
         return -1;

    if ( memcmp(&descriptor->AuthInfo.CertType, &gEfiCertPkcs7Guid, sizeof(EFI_GUID)) != 0 )
        return -1;

    descriptor_sz = OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) +
                        OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
    pkcert_list = (EFI_SIGNATURE_LIST*)(_ADDR(descriptor) + descriptor_sz);
    pkcert_data = pkcert_list_data(pkcert_list);

    if ( memcmp (&pkcert_list->SignatureType, &gEfiCertX509Guid, sizeof(EFI_GUID)) != 0 )
        return -1;

    *signature_data = &pkcert_data->SignatureData[0];
    *signature_len = pkcert_list->SignatureSize - sizeof(EFI_SIGNATURE_DATA) + 1;

    return 0;
}

/**
 * Returns a X509 cert on success, otherwise NULL.
 */
static X509 *x509_cert(void *data, size_t sz, bool sigdata_is_signed, EVP_PKEY *pkey)
{
    int ret;
    uint8_t *signature_data;
    uint64_t signature_data_len;

    ret = to_signature_data(&signature_data, &signature_data_len, data, sz);

    if ( ret < 0 )
        return NULL;

    if ( sigdata_is_signed )
    {
        if ( !pkey )
            return NULL;
    }

    return d2i_X509(NULL, (const unsigned char**) &signature_data, signature_data_len);
}


EFI_STATUS enroll_pk(EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
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
 * Handle the special case of setting the PK.
 */
static EFI_STATUS handle_set_pk(EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
{
    if ( !guid || !data )
        return EFI_DEVICE_ERROR;

    if ( ramdb_exists(PK_NAME) == VAR_NOT_FOUND )
        return enroll_pk(guid, attrs, datalen, data);

    if ( !pk_pubkey )
    {
        ERROR("BUG: PK variable exists, but varstored-ng has no key pair for PK saved\n");
        return EFI_DEVICE_ERROR;
    }

    return ProcessVarWithPk(PK_NAME, guid, data, datalen, attrs, true);
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

EFI_STATUS set_variable(UTF16 *variable, EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data)
{
    int ret;

    if ( !variable || !guid || !data )
        return -1;

    if ( is_ro(variable) )
        return EFI_WRITE_PROTECTED;

    if ( strcmp16(variable, PK_NAME) == 0 )
        return handle_set_pk(guid, attrs, datalen, data);

    ret = ramdb_set(variable, data, datalen, attrs);

    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}

/**
 * Return the names of current UEFI variables, one-by-one.
 *
 * This implements the UEFI Variable service GetNextVariableName()
 * function.
 *
 * @comm_buf:  The shared memory page with the OVMF XenVariable module.
 */
static void get_next_variable(void *comm_buf)
{
    uint32_t command;
    variable_t current;
    variable_t next;
    bool efi_at_runtime;
    uint64_t guest_bufsz;
    EFI_GUID guid;
    uint8_t *ptr = comm_buf;
    int ret;
    uint32_t version;

    memset(&current, 0, sizeof(current));
    memset(&next, 0, sizeof(next));

    version = unserialize_uint32(&ptr);

    if ( version != 1 )
        WARNING("OVMF appears to be running an unsupported version of the XenVariable module\n");

    command = unserialize_uint32(&ptr);
    assert(command == COMMAND_GET_NEXT_VARIABLE);

    guest_bufsz = unserialize_uintn(&ptr);
    current.namesz = unserialize_name(&ptr, current.name, MAX_VARNAME_SZ);
    unserialize_guid(&ptr, &guid);

    /* TODO: use the guid according to spec */
    (void)guid;

    efi_at_runtime = unserialize_boolean(&ptr);

    if ( efi_at_runtime )
    {
        /* TODO: does this information get used? */
    }

    ret = ramdb_next(&current, &next);
    if ( ret == 0 )
    {
        next_var_not_found(comm_buf);
        return;
    }

    if ( ret < 0 )
    {
        device_error(comm_buf);
        return;
    }

    if ( next.namesz > guest_bufsz )
    {
        WARNING("GetNextVariableName(), buffer too small: namesz: %lu, guest_bufsz: %lu\n",
                next.namesz, guest_bufsz);
        buffer_too_small(comm_buf, guest_bufsz, strsize16(next.name));
        return;
    }

    dprint_next_var(&current, &next);

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_name(&ptr, next.name);
    serialize_guid(&ptr, &guid);
}


void xenvariable_handle_request(void *comm_buf)
{
    uint8_t *ptr;
    uint32_t command;

    if ( !comm_buf )
    {
        ERROR("comm buffer is null!\n");
        return;
    }

    ptr = comm_buf;

    /* advance the pointer passed the version field */
    unserialize_uint32(&ptr);

    command = unserialize_uint32(&ptr);
    DEBUG("command=%d\n", command);

    switch ( command )
    {
        case COMMAND_GET_VARIABLE:
            handle_get_variable(comm_buf);
            break;
        case COMMAND_SET_VARIABLE:
            handle_set_variable(comm_buf);
            break;
        case COMMAND_GET_NEXT_VARIABLE:
            get_next_variable(comm_buf);
            break;
        case COMMAND_QUERY_VARIABLE_INFO:
            DEBUG("cmd:QUERY_VARIABLE_VARIABLE\n");
            break;
        case COMMAND_NOTIFY_SB_FAILURE:
            DEBUG("cmd:NOTIFY_SB_FAILURE\n");
            break;
        default:
            ERROR("cmd: unknown\n");
            break;
    }
}

void init_setup_mode(variable_t variables[MAX_VAR_COUNT], size_t n)
{
    /* If SETUP_MODE_NAME is already set, then we don't mess with it */
    if ( find_variable(SETUP_MODE_NAME, variables, n) )
        return;

    set_setup_mode(1);
}

void init_secure_boot(variable_t variables[MAX_VAR_COUNT], size_t n)
{
    if ( find_variable(SECURE_BOOT_NAME, variables, n) )
        return;

    set_secure_boot(0);
}

int xenvariable_init(var_initializer_t init_vars)
{
    int ret;
    variable_t variables[MAX_VAR_COUNT];
    variable_t *var;

    /* Initialize UEFI variables */
    ret = ramdb_init();
    if ( ret < 0 )
    {
        ERROR("Failed to initialize db: %d\n", ret);
        return ret;
    }

    if ( init_vars )
    {
        /* TODO: if there is an error, prevent boot.  If vars are empty, allow boot */
        ret = init_vars(variables, MAX_VAR_COUNT);

        if ( ret < 0 )
        {
            INFO("failed to get vars from xapi, starting with (ALMOST) blank DB\n");
        }

        if ( ret > 0 )
        {
            for_each_variable(variables, var) 
            {
                char ascii[MAX_VARNAME_SZ];
                uc2_ascii(var->name, ascii, MAX_VARNAME_SZ);
                DEBUG("%s: %s\n", ascii, var->data);
            }
        }
    }

    init_setup_mode(variables, MAX_VAR_COUNT);
    init_secure_boot(variables, MAX_VAR_COUNT);

    return 0;
}

int xenvariable_deinit(void)
{
    if ( pk_pubkey )
        EVP_PKEY_free(pk_pubkey);

    pk_pubkey = NULL;

    return 0;
}
