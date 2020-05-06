#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "backends/mem.h"
#include "common.h"
#include "parse.h"

#define VALIDATE_WRITES

int _logfd = -1;

/* UEFI Definitions */
typedef uint64_t EFI_STATUS;
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 2
#define EFI_BUFFER_TOO_SMALL 5
#define EFI_NOT_FOUND 14
#define EFI_SECURITY_VIOLATION 26

static char strbuf[512];
//static bool get_next_initialized = false;

typedef struct {
    uint32_t  data1;
    uint16_t  data2;
    uint16_t  data3;
    uint8_t   data4[8];
} efi_guid_t;

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
    uint8_t *p = mem;
    *p = value;

    return 1;
}

static size_t set_u32(void *mem, uint32_t value)
{
    uint32_t *p = mem;
    *p = value;

    return 4;
}

static size_t set_u64(void *mem, uint64_t value)
{
    uint64_t *p = mem;
    *p = value;

    return 8;
}

size_t set_data(void *mem, void *data, size_t datalen)
{
    memcpy(mem, data, datalen);

    return datalen;
}

size_t set_guid(void *shared_page, size_t initial_offset, uint8_t guid[16])
{
    size_t off = initial_offset;
    int i;

    for (i=0; i<16; i++)
    {
        off += set_u8(shared_page + off, guid[i]);
    }

    return 16;
}

#ifdef VALIDATE_WRITES
static void validate(void *variable_name, size_t len, void *data, size_t datalen, uint32_t attrs)
{
    int ret;
    void *test_data;
    uint32_t test_attrs;
    size_t test_datalen;

    ret = db_get(variable_name, len, &test_data, &test_datalen, &test_attrs);
    if ( ret < 0 )
    {
        ERROR("Failed to validate variable!\n");
        return;
    }

    if ( memcmp(test_data, data, datalen) )
        ERROR("Variable does not match!\n");
    else
        INFO("Variables match!\n");

    if ( attrs == test_attrs )
        ERROR("Attrs does not match!\n");
    else
        INFO("Attrs match!\n");

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

    if ( len == 0 )
    {
        INFO("UEFI Error: variable name len is 0\n");
        off = 0;
        off += set_u64(comm_buff + off, EFI_INVALID_PARAMETER);
        return;
    }

    if ( isnull(variable_name, len) )
    {
        INFO("UEFI Error: variable name is NULL\n");
        off = 0;
        off += set_u64(comm_buff + off, EFI_INVALID_PARAMETER);
        return;
    }

    DEBUG("cmd:GET_VARIABLE\n");
    dprint_vname(variable_name, len);

    ret = db_get(variable_name, len, &data, &datalen, &attrs);
    if ( ret < 0 )
    {
        off = 0;
        off += set_u64(comm_buff + off, EFI_NOT_FOUND);
        ERROR("Failed to get variable\n");
        return;
    }

    buflen = parse_datalen(comm_buff);
    if ( buflen < datalen )
    {
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
        off += set_data(comm_buff + off, data, datalen);
    }

    /* Free up any used memory */
    free(variable_name);
    free(data);
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
    attrs = parse_attrs(comm_buff);

    if ( datalen == 0 )
    {
        INFO("UEFI error: datalen == 0\n");
        set_u64(comm_buff, EFI_SECURITY_VIOLATION);
        return;
    }

    DEBUG("cmd:SET_VARIABLE\n");
    dprint_vname(variable_name, len);

    ret = db_set(variable_name, len, data, datalen, attrs);
    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        return;
    }

    validate(variable_name, len, data, datalen, attrs);
    set_u64(comm_buff, EFI_SUCCESS);


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

    if ( !db_iter_is_initialized() )
    {
        db_iter_init();
    }

    ret = db_iter_next(buffer, 128);
    if ( ret < 0 )
    {
        ERROR("db_iter_next() error\n");
    }
    else if ( ret == 0 )
    {
        DEBUG("db_iter_next() done!\n");
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
        //db_iter_init();
        //db_iter_next(variable_name, 
        off = 0;
        off += set_u64(comm_buff + off, EFI_SUCCESS);
    }
#endif

    free(variable_name);
#endif
}


void xenvariable_handle_request(void *comm_buff)
{

    DEBUG("version=%u\n", parse_version(comm_buff));

#if 1
    int i;
    DPRINTF("MESSAGE: ");
    for (i=0; i<128; i++)
    {
        DPRINTF("0x%x ", *((uint8_t*)(comm_buff + i)));
    }
    DPRINTF("\n");
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
