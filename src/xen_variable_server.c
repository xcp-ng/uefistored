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
#include "xapi.h"

//#define VALIDATE_WRITES

static void buffer_too_small(void *comm_buf, size_t required_size)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)required_size);
}

static void handle_get_variable(void *comm_buf)
{
    int namesz;
    EFI_GUID guid;
    uint32_t attrs, version;
    uint64_t buflen;
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    UTF16 *name;
    EFI_STATUS status;
    uint8_t *ptr = comm_buf;
    const uint8_t *inptr = comm_buf;

    inptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if ( version != VARSTORED_VERSION )
    {
        ERROR("Unsupported version of XenVariable RPC protocol\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if ( unserialize_uint32(&inptr) != COMMAND_GET_VARIABLE )
    {
        ERROR("BUG in varstored, wrong command\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    namesz = unserialize_namesz(&inptr);

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
        free(name);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, ptr), name, namesz + sizeof(UTF16));
    unserialize_guid(&inptr, &guid);

    buflen = unserialize_uint64(&inptr);

    status = get_variable(name, &guid, &attrs, &buflen, data);

    if ( status == EFI_BUFFER_TOO_SMALL )
    {
        free(name);
        buffer_too_small(comm_buf, buflen);
        return;
    }
    else if ( status )
    {
        free(name);
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }


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
    const uint8_t *inptr = comm_buf;

    ptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if ( version != VARSTORED_VERSION )
    {
        ERROR("Bad varstored version: %u\n", version);
        status = EFI_UNSUPPORTED;
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    command = unserialize_uint32(&inptr);

    if ( command != COMMAND_QUERY_VARIABLE_INFO )
    {
        ERROR("Bad command: %u\n", command);
        status = EFI_DEVICE_ERROR;
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    attrs = unserialize_uint32(&inptr);

    status = query_variable_info(attrs, &max_variable_storage, &remaining_variable_storage, &max_variable_size);;

    if ( status != EFI_SUCCESS )
    {
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    ptr = comm_buf;
    serialize_result(&ptr, status);
    serialize_value(&ptr, max_variable_storage);
    serialize_value(&ptr, remaining_variable_storage);
    serialize_value(&ptr, max_variable_size);
}

static void handle_set_variable(void *comm_buf)
{
    uint8_t *ptr;
    const uint8_t *inptr = comm_buf;
    EFI_GUID guid;
    int namesz;
    size_t datasz;
    UTF16 *name;
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    void *dp = data;
    uint32_t attrs, command, version;
    EFI_STATUS status;

    ptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if ( version != VARSTORED_VERSION )
    {
        ERROR("Invalid XenVariable OVMF module version number: %d, only supports version 1\n",
              version);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    command = unserialize_uint32(&inptr);
    if ( command != COMMAND_SET_VARIABLE )
    {
        ERROR("BUG: varstored accidentally passed a non SET_VARIABLE buffer to the"
              "%s function!, returning EFI_DEVICE_ERROR\n", __func__);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    namesz = unserialize_namesz(&inptr);

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
    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, inptr), name, namesz + sizeof(UTF16));
    unserialize_guid(&inptr, &guid);

    datasz = unserialize_data(&inptr, dp, MAX_VARIABLE_DATA_SIZE);
    attrs = unserialize_uint32(&inptr);

    status = set_variable(name, &guid, attrs, datasz, dp);

    ptr = comm_buf;
    serialize_result(&ptr, status);

    free(name);
}

static EFI_STATUS unserialize_get_next_variable(const void *comm_buf,
                                                uint64_t *namesz,
                                                UTF16 **name,
                                                uint64_t *guest_bufsz,
                                                EFI_GUID *guid)
{
    uint32_t command;
    bool efi_at_runtime;
    const uint8_t *inptr = comm_buf;
    uint32_t version;

    if ( !comm_buf || !namesz || !name || !guid )
        return EFI_DEVICE_ERROR;

    version = unserialize_uint32(&inptr);

    if ( version != VARSTORED_VERSION )
        WARNING("OVMF appears to be running an unsupported version of the XenVariable module\n");

    command = unserialize_uint32(&inptr);

    assert(command == COMMAND_GET_NEXT_VARIABLE);

    *guest_bufsz = unserialize_uintn(&inptr);
    *namesz = unserialize_namesz(&inptr);

    if ( *namesz > MAX_VARIABLE_NAME_SIZE )
        return EFI_DEVICE_ERROR;

    *name = malloc(*namesz + sizeof(UTF16));

    if ( !*name )
        return EFI_DEVICE_ERROR;

    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, inptr), *name, *namesz + sizeof(UTF16));
    unserialize_guid(&inptr, guid);

    /* TODO: use the guid according to spec */
    efi_at_runtime = unserialize_boolean(&inptr);

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
    const uint8_t *inptr = comm_buf;
    uint64_t guest_bufsz;
    UTF16 *name;
    uint64_t namesz;
    variable_t next;
    int ret;
    EFI_GUID guid;
    EFI_STATUS status;

    memset(&next, 0, sizeof(next));

    status = unserialize_get_next_variable(inptr, &namesz, &name, &guest_bufsz, &guid);

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
    const uint8_t *inptr = comm_buf;
    uint32_t command;

    if ( !comm_buf )
    {
        ERROR("comm buffer is null!\n");
        return;
    }
    /* advance the pointer passed the version field */
    unserialize_uint32(&inptr);

    command = unserialize_uint32(&inptr);

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

int xen_variable_server_init(void)
{
    int ret, i;
    char *name;
    variable_t variables[MAX_VAR_COUNT];

    memset(variables, 0, sizeof(variables));

    /* Initialize UEFI variables */
    storage_init();

    /* TODO: if there is an error, prevent boot.  If vars are empty, allow boot */
    ret = xapi_get_variables(variables, MAX_VAR_COUNT);

    if ( ret < 0 )
    {
        INFO("failed to get vars from xapi, starting with (ALMOST) blank DB\n");
    }

    for ( i=0; i<ret; i++ )
    {
        ret = storage_set(variables[i].name, variables[i].data,
                          variables[i].datasz, variables[i].attrs);

        if ( ret < 0 && variables[i].namesz > 0 )
        {
            name = malloc(variables[i].namesz / 2);
            memset(name, 0, 512);
            uc2_ascii_safe(variables[i].name, variables[i].namesz, name, 512);
            ERROR("failed to set variable: %s\n", name);
            free(name);
        }
    }

    return 0;
}

int xen_variable_server_deinit(void)
{
    return 0;
}
