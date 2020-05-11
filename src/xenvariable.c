#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "backends/filedb.h"
#include "xenvariable.h"
#include "serializer.h"
#include "uefitypes.h"
#include "common.h"
#include "parse.h"

//#define VALIDATE_WRITES

#define MAX_BUF (SHMEM_PAGES * PAGE_SIZE)
#define MAX_VARNAME_SZ (FILEDB_KEY_SIZE)

static char strbuf[512];

static void uc2_ascii(void *uc2, size_t uc2_len, char *ascii, size_t len)
{
    int i;
    int j = 0;

    for (i=0; i<uc2_len && j<(len-1); i++)
    {
        char c = *((char*)(uc2+i));
        if ( c != '\0' )
            ascii[j++] = c;
    }

    ascii[j++] = '\0';
}

/**
 * dprint_vname -  Debug print a variable name
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */
void dprint_vname(void *vn, size_t vnlen)
{
    uc2_ascii(vn, vnlen, strbuf, 512);
    DEBUG("name (%lu): %s\n", vnlen, strbuf);
    memset(strbuf, '\0', 512);
}


static bool isnull(void *mem, size_t len)
{
    uint8_t *p = mem;

    while ( len-- > 0 )
        if ( *(p++) != 0 )
            return false;

    return true;
}

static size_t set_u32(void *mem, uint32_t value)
{
    memcpy(mem, &value, sizeof(value));
    return sizeof(value);
}

static size_t set_u64(void *mem, uint64_t value)
{
    memcpy(mem, &value, sizeof(value));
    return sizeof(value);
}

static size_t set_data(void *mem, void *data, size_t datalen)
{
    memcpy(mem, data, datalen);

    return datalen;
}

static void dprint_data(void *data, size_t datalen)
{
    uint8_t *p = data;
    size_t i;

    DPRINTF("DATA: ");
    for (i=0; i<datalen; i++)
    {
        if (i % 8 == 0)
            DPRINTF("\n");
        DPRINTF("0x%x ", p[i]);
    }
    DPRINTF("\n");
}

#ifdef VALIDATE_WRITES
static void validate(void *variable_name, size_t len, void *data, size_t datalen, uint32_t attrs)
{
    int ret;
    void *test_data;
    uint32_t test_attrs = 0;
    size_t test_datalen;

    ret = filedb_get(variable_name, len, &test_data, &test_datalen, &test_attrs);
    if ( ret < 0 )
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

    DEBUG("******* Validate ********\n");
    dprint_vname(variable_name, len);
    DPRINTF("FROM DB: ");
    dprint_data(test_data, test_datalen);
    DPRINTF("FROM OVMF: ");
    dprint_data(data, datalen);
    DEBUG("*************************\n");

    free(test_data);
}
#else
#define validate(...) do { } while ( 0 )
#endif

static void get_variable(void *comm_buf)
{
    int ret;
    size_t len, datalen;
    uint32_t attrs;
    uint64_t buflen;
    void *data;
    void *variable_name;
    size_t off;

    parse_variable_name(comm_buf, &variable_name, &len);

    if ( len == 0 )
    {
        ERROR("UEFI Error: variable name len is 0\n");
        off = 0;
        off += set_u64(comm_buf + off, EFI_INVALID_PARAMETER);
        goto err;
    }

    if ( isnull(variable_name, len) )
    {
        INFO("UEFI Error: variable name is NULL\n");
        off = 0;
        off += set_u64(comm_buf + off, EFI_INVALID_PARAMETER);
        goto err;
    }

    ret = filedb_get(variable_name, len, &data, &datalen, &attrs);
    if ( ret < 0 )
    {
        off = 0;
        off += set_u64(comm_buf + off, EFI_NOT_FOUND);
        ERROR("Failed to get variable\n");
        goto err;
    }

    DEBUG("cmd:GET_VARIABLE\n");
    dprint_vname(variable_name, len);
    dprint_data(data, datalen);

    buflen = parse_datalen(comm_buf);
    if ( buflen < datalen )
    {
        WARNING("Buffer too small: 0x%lx < 0x%lx\n", buflen, datalen);
        off = 0;
        off += set_u64(comm_buf + off, EFI_BUFFER_TOO_SMALL);
        off += set_u64(comm_buf + off, datalen);
    }
    else
    {
        off = 0;
        off += set_u64(comm_buf + off, EFI_SUCCESS);
        off += set_u32(comm_buf + off, attrs);
        off += set_u64(comm_buf + off, datalen);
        if ( datalen + off > MAX_BUF )
        {
            ERROR("EFI_OUT_OF_RESOURCES: datalen=0x%lx, off=0x%lx\n", datalen, off);

            /* Reset previously written to zeroes */
            memset(comm_buf, 0, off);

            /* Send back EFI_OUT_OF_RESOURCES */
            off += set_u64(comm_buf, EFI_OUT_OF_RESOURCES);
        }
        else
        {
            off += set_data(comm_buf + off, data, datalen);
        }
    }

    free(data);

err:
    /* Free up any used memory */
    if ( variable_name )
        free(variable_name);
}

static void set_variable(void *comm_buf)
{
    uint8_t guid[16];
    size_t len, datalen;
    int ret;
    void *variable_name;
    void *data;
    uint32_t attrs;

    parse_variable_name(comm_buf, &variable_name, &len);
    parse_guid(comm_buf, guid);
    parse_data(comm_buf, &data, &datalen);

    /* TODO: Parse and implement attributes */
    attrs = parse_attrs(comm_buf);

    if ( datalen == 0 )
    {
        INFO("UEFI error: datalen == 0\n");
        set_u64(comm_buf, EFI_SECURITY_VIOLATION);
        goto end;
    }

    DEBUG("cmd:SET_VARIABLE\n");
    dprint_vname(variable_name, len);

    ret = filedb_set(variable_name, len, data, datalen, attrs);
    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        set_u64(comm_buf, EFI_OUT_OF_RESOURCES);
        goto end;
    }

    validate(variable_name, len, data, datalen, attrs);
    set_u64(comm_buf, EFI_SUCCESS);

end:
    free(variable_name);
    free(data);
}

static void next_var_not_found(void *comm_buf)
{
    uint8_t *ptr;

    ptr = comm_buf;
    serialize_result(&ptr, EFI_NOT_FOUND);
}

static void device_error(void *comm_buf)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_DEVICE_ERROR);
}

static void buffer_too_small(void *comm_buf, size_t namesz)
{
    uint8_t *ptr = comm_buf;

    WARNING("GetNextVariableName() buffer too small, return EFI_BUFFER_TOO_SMALL\n");
    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)namesz);
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
    variable_t current, next;
    bool efi_at_runtime;
    uint64_t guest_bufsz;
    EFI_GUID guid;
    uint8_t *ptr = comm_buf;
    int ret;
    uint32_t version;

    DEBUG("cmd:GET_NEXT_VARIABLE_NAME\n");

    version = unserialize_uint32(&ptr);

    if ( version != 1 )
        WARNING("OVMF appears to be running an unsupported version of the XenVariable module\n");

    command = unserialize_uint32(&ptr);
    assert(command == COMMAND_GET_NEXT_VARIABLE);

    guest_bufsz = unserialize_uintn(&ptr);
    unserialize_name(&ptr, &current.name[0], MAX_VARNAME_SZ);
    current.namesz = strsize16((char16_t*)current.name);
    unserialize_guid(&ptr, &guid);

    /* TODO: use the guid according to spec */
    (void)guid;

    efi_at_runtime = unserialize_boolean(&ptr);

    if ( efi_at_runtime )
    {
        /* TODO: does this information get used? */
    }

    ret = filedb_variable_next(&current, &next);
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
        buffer_too_small(comm_buf, next.namesz);
        return;
    }

    dprint_vname(&next.name, next.namesz);

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_data(&ptr, &next.name, next.namesz);
    serialize_guid(&ptr, &guid);
}


void xenvariable_handle_request(void *comm_buf)
{
    if ( !comm_buf )
    {
        ERROR("comm buffer is null!\n");
        return;
    }

    switch ( parse_command(comm_buf) )
    {
        case COMMAND_GET_VARIABLE:
            get_variable(comm_buf);
            break;
        case COMMAND_SET_VARIABLE:
            set_variable(comm_buf);
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
