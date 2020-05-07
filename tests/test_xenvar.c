#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "mock/XenVariable.h"
#include "test_common.h"
#include "parse.h"

#define DEBUG 1

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static void test_getvar(void)
{
    char namebytes[] = {
        0, 'h',
        0, 'e',
        0, 'l',
        0, 'l', 
        0, 'o',
        0,  0
    };
    char16_t *name = (char16_t*)namebytes;
    EFI_GUID guid = { .guid = {0} };
    uint8_t test_guid[16];
    uint32_t attr = 0;
    uint64_t datasize = 4;
    uint64_t data = 0xdeadbeef;

    void *vnp;
    size_t len;


    guid.guid[0] = 0xde;
    XenGetVariable(name, &guid, &attr, &datasize, (void*)&data);
    test(parse_command(comm_buf) == COMMAND_GET_VARIABLE);
    parse_variable_name(comm_buf, &vnp, &len);
    test(len == 10);
    test(memcmp(vnp, namebytes, 10) == 0);
    parse_guid(comm_buf, test_guid);
    test(memcmp(test_guid, &guid, 16) == 0);

    free(vnp);
}

void test_xenvar(void)
{
    mock_xenvariable_set_buffer(comm_buf);
    test_getvar();
}
