#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

#include "storage.h"
#include "common.h"
#include "info.h"
#include "log.h"
#include "serializer.h"
#include "uefi/types.h"
#include "uefi/guids.h"
#include "varnames.h"
#include "variables_service.h"
#include "xen_variable_server.h"

//#define VALIDATE_WRITES

#if DEBUG_XEN_VARIABLE_SERVER
/**
 * dprint_vname -  Debug print a variable name
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */
#define dprint_vname(format, vn, ...) \
do { \
    uc2_ascii_safe(vn, strsize16(vn), strbuf, 512); \
    DEBUG(format, strbuf __VA_ARGS__); \
    memset(strbuf, '\0', 512); \
} while ( 0 )

#else
#define dprint_vname(...) do { } while ( 0 )
#endif

#if DEBUG_XEN_VARIABLE_SERVER
#define eprint_vname(format, vn, ...) \
do { \
    uc2_ascii_safe(vn, strsize16(vn), strbuf, 512); \
    ERROR(format, strbuf __VA_ARGS__); \
    memset(strbuf, '\0', 512); \
} while( 0 )
#else
#define eprint_vname(...) do { } while ( 0 )
#endif

static int set_setup_mode(uint8_t val)
{
    int ret;

    ret = storage_set(SETUP_MODE_NAME,
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

    ret = storage_set(SECURE_BOOT_NAME,
                   &val,
                   sizeof(val),
                   EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);

    if ( ret < 0 )
        ERROR("%s:%d: Failed to set SECURE_BOOT_NAME to %u!\n", __func__, __LINE__, val);

    return ret;
}

static void dprint_attrs(uint32_t attr)
{
#if DEBUG_XEN_VARIABLE_SERVER
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
#endif
}

static void buffer_too_small(void *comm_buf, size_t required_size)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)required_size);
}

void print_uc2(const char *TAG, void *vn)
{
#if DEBUG_XEN_VARIABLE_SERVER
    uc2_ascii(vn, strbuf, 512);
    DEBUG("%s:%s\n", TAG, strbuf);
    memset(strbuf, '\0', 512);
#endif
}

#ifdef VALIDATE_WRITES
static void validate(void *name, size_t len, void *data, size_t datasz, uint32_t attrs)
{
    int ret;
    uint8_t test_data[MAX_VARIABLE_DATA_SIZE];
    uint32_t test_attrs = 0;
    size_t test_datasz;

    (void) len;

    ret = storage_get(name, test_data, MAX_VARIABLE_DATA_SIZE, &test_datasz, &test_attrs);

    if ( datasz == 0 && ret == VAR_NOT_FOUND )
    {
        DEBUG("Variable successfully deleted!\n");
        return;
    }
    else if ( ret != 0 )
    {
        ERROR("%s: failed to get variable with storage_get(), ret=%d!\n", __func__, ret);
        return;
    }

    if ( memcmp(test_data, data, datasz) )
        ERROR("Variable does not match!\n");
    else
        INFO("Variables match!\n");

    if ( attrs != test_attrs )
        ERROR("Attrs does not match!\n");
    else
        INFO("Attrs match!\n");

    dprint_vname("Validate: %s\n", name);
    DPRINTF("FROM DB: ");
    dprint_data(test_data, test_datasz);
    DPRINTF("FROM OVMF: ");
    dprint_data(data, datasz);
    DEBUG("*************************\n");
}
#else
#define validate(...) do { } while ( 0 )
#endif

static void handle_get_variable(void *comm_buf)
{
    int namesz;
    EFI_GUID guid;
    uint32_t attrs, version;
    uint64_t buflen;
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    UTF16 *name;
    EFI_STATUS status;
    uint8_t *ptr;

    ptr = comm_buf;
    version = unserialize_uint32(&ptr);

    if ( version != VARSTORED_VERSION )
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

    namesz = unserialize_namesz(&ptr);

    if ( namesz <= 0 )
    {
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    name = malloc(namesz + sizeof(UTF16));

    if ( !name )
    {
        ptr = comm_buf;
        buffer_too_small(comm_buf, MAX_VARIABLE_NAME_SIZE);
        return;
    }

    if ( namesz > MAX_VARIABLE_NAME_SIZE )
    {
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    unserialize_name(&ptr, BUFFER_REMAINING(comm_buf, ptr), name, namesz + sizeof(UTF16));
    unserialize_guid(&ptr, &guid);

    buflen = unserialize_uint64(&ptr);

    status = get_variable(name, &guid, &attrs, &buflen, data);

    if ( status == EFI_BUFFER_TOO_SMALL )
    {
        buffer_too_small(comm_buf, buflen);
        free(name);
        return;
    }
    else if ( status )
    {
        ptr = comm_buf;
        dprint_vname("cmd:GET_VARIABLE: %s, ", name);
        DPRINTF("error=0x%02lx\n", status);
        serialize_result(&ptr, status);
        free(name);
        return;
    }


    dprint_vname("cmd:GET_VARIABLE: %s\n", name);

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint32(&ptr, attrs);
    serialize_data(&ptr, data, buflen);

    free(name);
}

static void handle_query_variable_info(void *comm_buf)
{
    uint32_t attrs, version, command;
    EFI_STATUS status;
    uint8_t *ptr;
    uint64_t max_variable_storage;
    uint64_t remaining_variable_storage;
    uint64_t max_variable_size;

    ptr = comm_buf;
    version = unserialize_uint32(&ptr);

    if ( version != VARSTORED_VERSION )
    {
        ERROR("Bad varstored version: %u\n", version);
        status = EFI_UNSUPPORTED;
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    command = unserialize_uint32(&ptr);

    if ( command != COMMAND_QUERY_VARIABLE_INFO )
    {
        ERROR("Bad command: %u\n", command);
        status = EFI_DEVICE_ERROR;
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    attrs = unserialize_uint32(&ptr);

    status = query_variable_info(attrs, &max_variable_storage, &remaining_variable_storage, &max_variable_size);;

    if ( status != EFI_SUCCESS )
    {
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    ptr = comm_buf;
    serialize_result(&ptr, status);
    printf(">>>>>>>>>> 0x%02lx\n", max_variable_storage);
    serialize_value(&ptr, max_variable_storage);
    serialize_value(&ptr, remaining_variable_storage);
    serialize_value(&ptr, max_variable_size);
}

static void print_set_var(UTF16 *name, size_t len, uint32_t attrs)
{
    dprint_vname("cmd:SET_VARIABLE: %s, attrs=", name);
    dprint_attrs(attrs);
    DPRINTF("\n");
}

static void handle_set_variable(void *comm_buf)
{
    uint8_t *ptr;
    EFI_GUID guid;
    int namesz;
    size_t datasz;
    UTF16 *name;
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    void *dp = data;
    uint32_t attrs, command, version;
    EFI_STATUS status;

    ptr = comm_buf;
    version = unserialize_uint32(&ptr);

    if ( version != VARSTORED_VERSION )
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

    namesz = unserialize_namesz(&ptr);

    if ( namesz <= 0 )
    {
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if ( namesz > MAX_VARIABLE_NAME_SIZE )
    {

        buffer_too_small(comm_buf,
                min(MAX_STORAGE_SIZE - storage_used(), MAX_VARIABLE_NAME_SIZE));
        return;
    }

    name = malloc(namesz + sizeof(UTF16));
    unserialize_name(&ptr, BUFFER_REMAINING(comm_buf, ptr), name, namesz + sizeof(UTF16));
    unserialize_guid(&ptr, &guid);

    datasz = unserialize_data(&ptr, dp, MAX_VARIABLE_DATA_SIZE);
    attrs = unserialize_uint32(&ptr);

    print_set_var(name, namesz, attrs);

    status = set_variable(name, &guid, attrs, datasz, dp);
    validate(name, namesz, dp, datasz, attrs);

    ptr = comm_buf;
    serialize_result(&ptr, status);

    free(name);
}

static EFI_STATUS unserialize_get_next_variable(void *comm_buf,
                                                uint64_t *namesz,
                                                UTF16 **name,
                                                uint64_t *guest_bufsz,
                                                EFI_GUID *guid)
{
    uint32_t command;
    bool efi_at_runtime;
    uint8_t *ptr = comm_buf;
    uint32_t version;

    if ( !comm_buf || !namesz || !name || !guid )
        return EFI_DEVICE_ERROR;

    version = unserialize_uint32(&ptr);

    if ( version != VARSTORED_VERSION )
        WARNING("OVMF appears to be running an unsupported version of the XenVariable module\n");

    command = unserialize_uint32(&ptr);

    assert(command == COMMAND_GET_NEXT_VARIABLE);

    *guest_bufsz = unserialize_uintn(&ptr);
    *namesz = unserialize_namesz(&ptr);

    if ( *namesz > MAX_VARIABLE_NAME_SIZE )
        return EFI_DEVICE_ERROR;

    *name = malloc(*namesz + sizeof(UTF16));

    if ( !*name )
        return EFI_DEVICE_ERROR;

    unserialize_name(&ptr, BUFFER_REMAINING(comm_buf, ptr), *name, *namesz + sizeof(UTF16));
    unserialize_guid(&ptr, guid);

    /* TODO: use the guid according to spec */
    efi_at_runtime = unserialize_boolean(&ptr);

    if ( efi_at_runtime )
    {
        /* TODO: does this information get used? */
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
static void handle_get_next_variable(void *comm_buf)
{
    uint8_t *ptr = comm_buf;
    uint64_t guest_bufsz;
    UTF16 *name;
    uint64_t namesz;
    variable_t next;
    int ret;
    EFI_GUID guid;
    EFI_STATUS status;

    memset(&next, 0, sizeof(next));

    status = unserialize_get_next_variable(ptr, &namesz, &name, &guest_bufsz, &guid);

    if ( status )
    {
        serialize_result(&ptr, status);
        return;
    }

    ret = storage_next(&next);

    if ( ret == 0 )
    {
        status = EFI_NOT_FOUND;
        serialize_result(&ptr, status);
        goto cleanup1;
    }
    else if ( ret < 0 )
    {
        status = EFI_DEVICE_ERROR;
        serialize_result(&ptr, status);
        goto cleanup2;
    }
    else if ( next.namesz > guest_bufsz )
    {
        WARNING("GetNextVariableName(), buffer too small: namesz: %lu, guest_bufsz: %lu\n",
                next.namesz, guest_bufsz);
        buffer_too_small(comm_buf, strsize16(next.name));
        goto cleanup2;
    }

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_name(&ptr, next.name);
    serialize_guid(&ptr, &next.guid);

cleanup2:
    variable_destroy_noalloc(&next);
cleanup1:
    free(name);
}


void xen_variable_server_handle_request(void *comm_buf)
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

    switch ( command )
    {
        case COMMAND_GET_VARIABLE:
            handle_get_variable(comm_buf);
            break;
        case COMMAND_SET_VARIABLE:
            handle_set_variable(comm_buf);
            break;
        case COMMAND_GET_NEXT_VARIABLE:
            handle_get_next_variable(comm_buf);
            break;
        case COMMAND_QUERY_VARIABLE_INFO:
            handle_query_variable_info(comm_buf);
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

int xen_variable_server_init(var_initializer_t init_vars)
{
    int ret;
    variable_t variables[MAX_VAR_COUNT];
    variable_t *var;

    memset(variables, 0, sizeof(variables));

    /* Initialize UEFI variables */
    ret = storage_init();
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
                ret = storage_set(var->name, var->data, var->datasz, var->attrs);

                if ( ret < 0 )
                    ERROR("failed to set variable\n");
            }
        }
    }

    init_setup_mode(variables, storage_count());
    init_secure_boot(variables, storage_count());

    return 0;
}

int xen_variable_server_deinit(void)
{
    return 0;
}
