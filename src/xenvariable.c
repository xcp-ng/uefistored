#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "backends/filedb.h"
#include "xenvariable.h"
#include "common.h"
#include "parse.h"

#define VALIDATE_WRITES
#define MAX_BUF (SHMEM_PAGES * PAGE_SIZE)
static char strbuf[512];
//static bool get_next_initialized = false;

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

static size_t set_u8(void *mem, uint8_t value)
{
    memcpy(mem, &value, sizeof(value));
    return sizeof(value);
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

static size_t set_guid(void *shared_page, size_t initial_offset, uint8_t guid[16])
{
    size_t off = initial_offset;
    int i;

    for (i=0; i<16; i++)
    {
        off += set_u8(shared_page + off, guid[i]);
    }

    return 16;
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

static void get_variable(void *comm_buff)
{
    int ret;
    size_t len, datalen;
    uint32_t attrs;
    uint64_t buflen;
    void *data;
    void *variable_name;
    size_t off;

    parse_variable_name(comm_buff, &variable_name, &len);

    DEBUG("len=%lu\n", len);
    if ( len == 0 )
    {
        INFO("UEFI Error: variable name len is 0\n");
        off = 0;
        off += set_u64(comm_buff + off, EFI_INVALID_PARAMETER);
        goto err;
    }

    if ( isnull(variable_name, len) )
    {
        INFO("UEFI Error: variable name is NULL\n");
        off = 0;
        off += set_u64(comm_buff + off, EFI_INVALID_PARAMETER);
        goto err;
    }

    ret = filedb_get(variable_name, len, &data, &datalen, &attrs);
    if ( ret < 0 )
    {
        off = 0;
        off += set_u64(comm_buff + off, EFI_NOT_FOUND);
        ERROR("Failed to get variable\n");
        goto err;
    }

    DEBUG("cmd:GET_VARIABLE\n");
    dprint_vname(variable_name, len);
    dprint_data(data, datalen);

    buflen = parse_datalen(comm_buff);
    if ( buflen < datalen )
    {
        WARNING("Buffer too small: 0x%x < 0x%x\n", buflen, datalen);
        off = 0;
        off += set_u64(comm_buff + off, EFI_BUFFER_TOO_SMALL);
        off += set_u64(comm_buff + off, datalen);
    }
    else
    {
        off = 0;
        off += set_u64(comm_buff + off, EFI_SUCCESS);
        off += set_u32(comm_buff + off, attrs);
        off += set_u64(comm_buff + off, datalen);
        if ( datalen + off > MAX_BUF )
        {
            ERROR("EFI_OUT_OF_RESOURCES: datalen=0x%x, off=0x%x\n", datalen, off);

            /* Reset previously written to zeroes */
            memset(comm_buff, 0, off);

            /* Send back EFI_OUT_OF_RESOURCES */
            off += set_u64(comm_buff, EFI_OUT_OF_RESOURCES);
        }
        else
        {
            off += set_data(comm_buff + off, data, datalen);
        }
    }

    free(data);

err:
    /* Free up any used memory */
    if ( variable_name )
        free(variable_name);
}

static void set_variable(void *comm_buff)
{
    uint8_t guid[16];
    size_t len, datalen;
    int ret;
    void *variable_name;
    void *data;
    uint32_t attrs;

    parse_variable_name(comm_buff, &variable_name, &len);
    parse_guid(comm_buff, guid);
    parse_data(comm_buff, &data, &datalen);

    /* TODO: Parse and implement attributes */
    attrs = parse_attrs(comm_buff);

    if ( datalen == 0 )
    {
        INFO("UEFI error: datalen == 0\n");
        set_u64(comm_buff, EFI_SECURITY_VIOLATION);
        goto end;
    }

    DEBUG("cmd:SET_VARIABLE\n");
    dprint_vname(variable_name, len);

    ret = filedb_set(variable_name, len, data, datalen, attrs);
    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        set_u64(comm_buff, EFI_OUT_OF_RESOURCES);
        goto end;
    }

    validate(variable_name, len, data, datalen, attrs);
    set_u64(comm_buff, EFI_SUCCESS);

end:
    free(variable_name);
    free(data);
}

static void get_next_variable(void *comm_buff)
{
    (void) comm_buff;
#if 0
    uint8_t guid[16];
    uint8_t buffer[128] = {0};
    void *variable_name;
    size_t bufsize;
    size_t len, off;
    int ret;

    bufsize = parse_variable_name_size(comm_buff);
    parse_variable_name_next(comm_buff, &variable_name, &len);

    DEBUG("cmd:GET_NEXT_VARIABLE\n");

    if ( !filedb_iter_is_initialized() )
    {
        filedb_iter_init();
    }

    ret = filedb_iter_next(buffer, 128);
    if ( ret < 0 )
    {
        ERROR("filedb_iter_next() error\n");
    }
    else if ( ret == 0 )
    {
        DEBUG("filedb_iter_next() done!\n");
    }
    else
    {
        len = ret;
        off = 0;
        off += set_u64(comm_buff + off, EFI_SUCCESS);
        off += set_u64(comm_buff + off, len);
        memcpy(comm_buff, buffer, len);
        off += len;
        off += set_guid(comm_buff, off, guid);
    }
        
#if 0
    dprint_vname(variable_name, len);
    if ( isnull(variable_name, len) && len == 0 )
    {
        //filedb_iter_init();
        //filedb_iter_next(variable_name, 
        off = 0;
        off += set_u64(comm_buff + off, EFI_SUCCESS);
    }
#endif

    free(variable_name);
#endif
}


void xenvariable_handle_request(void *comm_buff)
{

    int i;
    uint8_t val;
    DEBUG("version=%u\n", parse_version(comm_buff));

#if 1
    if ( comm_buff )
    {
        DPRINTF("MESSAGE: ");
        for (i=0; i<128; i++)
        {
            uint8_t val = ((uint8_t*)comm_buff)[i];
            DPRINTF("0x%.2x ", (uint64_t)val);
        }
        DPRINTF("\n");
    }
#endif

    switch ( parse_command(comm_buff) )
    {
        case COMMAND_GET_VARIABLE:
            get_variable(comm_buff);
            break;
        case COMMAND_SET_VARIABLE:
            set_variable(comm_buff);
            break;
        case COMMAND_GET_NEXT_VARIABLE:
            get_next_variable(comm_buff);
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
