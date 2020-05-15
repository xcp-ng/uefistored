#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "backends/filedb.h"
#include "xenvariable.h"
#include "serializer.h"
#include "UefiMultiPhase.h"
#include "uefitypes.h"
#include "common.h"
#include "parse.h"

//#define VALIDATE_WRITES

#define MAX_BUF (SHMEM_PAGES * PAGE_SIZE)
#define MAX_DATA_SZ (FILEDB_VAL_SIZE)

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

static char strbuf[512];


/**
 * dprint_vname -  Debug print a variable name
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */
#define dprint_vname(format, vn, vnlen, ...) \
do { \
    uc2_ascii_safe(vn, vnlen, strbuf, 512); \
    DEBUG(format, strbuf __VA_ARGS__); \
    memset(strbuf, '\0', 512); \
} while ( 0 )

#define eprint_vname(format, vn, vnlen, ...) \
do { \
    uc2_ascii_safe(vn, vnlen, strbuf, 512); \
    ERROR(format, strbuf __VA_ARGS__); \
    memset(strbuf, '\0', 512); \
} while( 0 )

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

static bool name_eq(void *vn, size_t vnlen, const char *comp)
{
    uc2_ascii_safe(vn, vnlen, strbuf, 512);
    return memcmp(strbuf, comp, vnlen / 2) == 0;
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
    uint8_t test_data[MAX_DATA_SZ];
    uint32_t test_attrs = 0;
    size_t test_datalen;

    ret = filedb_get(variable_name, len, test_data, MAX_DATA_SZ, &test_datalen, &test_attrs);
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

    dprint_vname("Validate: %s\n", variable_name, len);
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
    EFI_GUID guid;
    uint32_t attrs, version;
    uint64_t buflen;
    uint8_t data[MAX_DATA_SZ];
    char variable_name[MAX_VARNAME_SZ];
    size_t off;

    uint8_t *ptr;

    ptr = comm_buf;
    version = unserialize_uint32(&ptr);
    if ( version != 1 )
    {
        ERROR("Unsupported version of XenVariable RPC protocol\n");
        return;
    }

    if ( unserialize_uint32(&ptr) != COMMAND_GET_VARIABLE )
    {
        ERROR("BUG in varstored, wrong command\n");
        return;
    }

    len = unserialize_name(&ptr, variable_name, MAX_VARNAME_SZ);
    if ( len == 0 )
    {
        ERROR("cmd:GET_VARIABLE: UEFI Error: variable name len is 0\n");
        off = 0;
        off += set_u64(comm_buf + off, EFI_INVALID_PARAMETER);
        return;
    }

    if ( isnull(variable_name, len) )
    {
        DEBUG("cmd:GET_VARIABLE: UEFI Error, variable name is NULL\n");
        off = 0;
        off += set_u64(comm_buf + off, EFI_INVALID_PARAMETER);
        return;
    }

    ret = filedb_get(variable_name, len, data, MAX_DATA_SZ, &datalen, &attrs);
    if ( ret == 1 )
    {
        off = 0;
        off += set_u64(comm_buf + off, EFI_NOT_FOUND);
        dprint_vname("cmd:GET_VARIABLE: %s, not in DB\n", variable_name, len);
        return;
    }

    if ( ret < 0 )
    {
        off = 0;
        off += set_u64(comm_buf + off, EFI_DEVICE_ERROR);
        dprint_vname("cmd:GET_VARIABLE: %s, varstored error\n", variable_name, len);
        return;
    }

    unserialize_guid(&ptr, &guid);

    buflen = unserialize_uint64(&ptr);
    if ( buflen < datalen )
    {
        dprint_vname("cmd:GET_VARIABLE: %s, buffer too small\n", variable_name, len);
        off = 0;
        off += set_u64(comm_buf + off, EFI_BUFFER_TOO_SMALL);
        off += set_u64(comm_buf + off, datalen);
        return;
    }

    /* This should NEVER happen.  Indicates a varstored bug */
    if ( datalen > MAX_BUF )
    {
        off = 0;
        eprint_vname("BUG:cmd:GET_VARIABLE: %s, EFI_OUT_OF_RESOURCES\n", variable_name, len);

        /* Reset previously written to zeroes */
        memset(comm_buf, 0, off);

        /* Send back EFI_OUT_OF_RESOURCES */
        off += set_u64(comm_buf, EFI_OUT_OF_RESOURCES);
        return;
    }

    off = 0;
    off += set_u64(comm_buf + off, EFI_SUCCESS);
    off += set_u32(comm_buf + off, attrs);
    off += set_u64(comm_buf + off, datalen);
    off += set_data(comm_buf + off, data, datalen);

    dprint_vname("cmd:GET_VARIABLE: %s\n", variable_name, len);
    dprint_data(data, datalen);
}

static void print_set_var(char *variable_name, size_t len, uint32_t attrs)
{
    dprint_vname("cmd:SET_VARIABLE: %s, attrs=", variable_name, len);
    dprint_attrs(attrs);
    DPRINTF("\n");
}

static void set_variable(void *comm_buf)
{
    uint8_t *ptr;
    EFI_GUID guid;
    size_t len, datalen;
    int ret;
    char variable_name[MAX_VARNAME_SZ];
    uint8_t data[MAX_DATA_SZ];
    void *dp = data;
    uint32_t attrs, command, version;

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
    unserialize_guid(&ptr, &guid);
    datalen = unserialize_data(&ptr, dp, MAX_DATA_SZ);
    attrs = unserialize_uint32(&ptr);

    if ( datalen == 0 )
    {
        ERROR("UEFI error: datalen == 0\n");
        print_set_var(variable_name, len, attrs);
        set_u64(comm_buf, EFI_SECURITY_VIOLATION);
        return;
    }

#if 1
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
    print_set_var(variable_name, len, attrs);

    ret = filedb_set(variable_name, len, dp, datalen, attrs);
    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        set_u64(comm_buf, EFI_OUT_OF_RESOURCES);
        return;
    }

    validate(variable_name, len, dp, datalen, attrs);
    set_u64(comm_buf, EFI_SUCCESS);
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

static void buffer_too_small(void *comm_buf, size_t namesz)
{
    uint8_t *ptr = comm_buf;
    WARNING("EFI_BUFFER_TOO_SMALL, requires bufsz: %lu\n", namesz);

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
    variable_t current = {{0}};
    variable_t next = {{0}};
    bool efi_at_runtime;
    uint64_t guest_bufsz;
    EFI_GUID guid;
    uint8_t *ptr = comm_buf;
    int ret;
    uint32_t version;

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
        WARNING("GetNextVariableName(), %s, buffer too small: namesz: %lu, guest_bufsz: %lu\n",
                next.name, next.namesz, guest_bufsz);
        buffer_too_small(comm_buf, next.namesz);
        return;
    }

    dprint_next_var(&current, &next);

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_data(&ptr, &next.name, next.namesz);
    serialize_guid(&ptr, &guid);
}


void xenvariable_handle_request(void *comm_buf)
{
    uint8_t *ptr;

    if ( !comm_buf )
    {
        ERROR("comm buffer is null!\n");
        return;
    }

    ptr = comm_buf;

    /* advance the pointer passed the version field */
    unserialize_uint32(&ptr);

    switch ( unserialize_uint32(&ptr) )
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
