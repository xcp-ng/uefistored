#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "xenvariable.h"
#include "backends/filedb.h"
#include "mock/XenVariable.h"
#include "test_common.h"
#include "common.h"

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

#define DO_TEST(test)                                   \
    do  {                                               \
        test();                                         \
        memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);   \
    }  while ( 0 )

int _logfd = -1;

/* Test Data */
const char rtcnamebytes[] = {
    0, 'R',
    0, 'T',
    0, 'C',
    0,  0,
};

static void init(void)
{
    int ret;

    ret = filedb_init("./test.db", "./test_var_len.db", "./test_var_attrs.db");
    test(ret == 0);
}

static inline uint64_t getstatus(void *p)
{
    return *((uint64_t*) p);
}

static void deinit(void)
{
    filedb_deinit();
}

static void test_nonexistent_variable_returns_not_found(void)
{
    uint64_t status;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr;
    uint64_t datasize;
    uint64_t data;
    void *vnp;
    size_t len;

    mock_xenvariable_set_buffer(comm_buf);

    guid[0] = 0xde;

    /* Build a GetVariable() command */
    XenGetVariable(rtcname, &guid, &attr, &datasize, (void*)&data);

    /* Handle the command */
    xenvariable_handle_request(comm_buf);

    status = *((uint64_t*) comm_buf);
    test(status == EFI_NOT_FOUND);
}

static void test_get_and_set(void)
{
    uint64_t status;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint8_t test_guid[16];
    uint32_t attr = 0;


    uint64_t datasize;
    uint64_t data;

    uint64_t newdatasize = 4;
    uint64_t newdata = 0xdeadbeef;

    void *vnp;
    size_t len;

    mock_xenvariable_set_buffer(comm_buf);

    assert(getstatus(comm_buf) != EFI_NOT_FOUND);

    /* Build a GetVariable() command */
    XenGetVariable(rtcname, &guid, &attr, &datasize, (void*)&data);

    /* Handle the command */
    xenvariable_handle_request(comm_buf);
}


static void test_good_commands(void)
{
}

static void test_bad_commands(void)
{
    /* TODO: test large values, fuzz, etc... */
    test(0);
}

void test_xenvariable(void)
{
    init();

    DO_TEST(test_nonexistent_variable_returns_not_found);
    DO_TEST(test_get_and_set);

    deinit();
}
