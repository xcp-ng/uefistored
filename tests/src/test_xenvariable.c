#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "xenvariable.h"
#include "backends/filedb.h"
#include "mock/XenVariable.h"
#include "test_common.h"
#include "UefiMultiPhase.h"
#include "uefitypes.h"
#include "serializer.h"
#include "common.h"

#define DEFAULT_ATTR (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static void pre_test(void)
{
    filedb_init("./test.db", "./test_var_len.db", "./test_var_attrs.db");
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

static void post_test(void)
{
    filedb_deinit();
    filedb_destroy();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

/* Test Data */
char rtcnamebytes[] = {
    0, 'R',
    0, 'T',
    0, 'C',
    0,  0,
};

char mtcnamebytes[] = {
    0, 'M',
    0, 'T',
    0, 'C',
    0,  0,
};

static inline uint64_t getstatus(void *p)
{
    uint64_t ret;

    memcpy(&ret, p, sizeof(ret));

    return ret;
}

static void test_nonexistent_variable_returns_not_found(void)
{
    uint8_t *ptr;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr;
    uint64_t data;
    uint64_t datasize = sizeof(data);
    EFI_STATUS status;

    comm_buf = comm_buf_phys;
    mock_xenvariable_set_buffer(comm_buf);

    guid[0] = 0xde;

    /* Build a GetVariable() command */
    XenGetVariable(rtcname, &guid, &attr, &datasize, (void*)&data);
    ptr = comm_buf;
    status = unserialize_result(&ptr);

    /* Handle the command */
    xenvariable_handle_request(comm_buf);

   // xenvariable_handle_request(comm_buf);
    test(getstatus(comm_buf) == EFI_NOT_FOUND);
}

static EFI_STATUS deserialize_xen_get_var_response(
        void *buf,
        uint32_t *Attributes,
        void *Data,
        size_t *DataSize)
{
    uint32_t attr;
    uint8_t *ptr = buf;
    EFI_STATUS status;

    status = unserialize_result(&ptr);
    switch ( status )
    {
    case EFI_SUCCESS:
        if (!Data)
            return EFI_INVALID_PARAMETER;
        attr = unserialize_uint32(&ptr);
        if (Attributes)
            *Attributes = attr;
        unserialize_data(&ptr, Data, DataSize);
        break;
    case EFI_BUFFER_TOO_SMALL:
        *DataSize = unserialize_uintn(&ptr);
        break;
    default:
        break;
    }

    return status;
}

static EFI_STATUS deserialize_xen_get_next_var_response(
     uint64_t             *VariableNameSize,
     char16_t            *VariableName,
     EFI_GUID          *VendorGuid
  )
{
  uint8_t *ptr;
  EFI_STATUS status;

  ptr = comm_buf;
  status = unserialize_result(&ptr);
  switch (status) {
  case EFI_SUCCESS:
    unserialize_data(&ptr, VariableName, VariableNameSize);
    VariableName[*VariableNameSize / 2] = '\0';
    *VariableNameSize = sizeof(*VariableName);
    unserialize_guid(&ptr, VendorGuid);
    break;
  case EFI_BUFFER_TOO_SMALL:
    *VariableNameSize = unserialize_uintn(&ptr);
    break;
  default:
    break;
  }
  return status;
}


/**
 * SetVariable() deserializes to the status field.
 *
 * Returns the status code on the buffer.
 */
static EFI_STATUS deserialize_set_variable_response(void *buf)
{
    return getstatus(buf);
}

/* Helpers */
static void set_rtc_variable(void *buf)
{
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;

    mock_xenvariable_set_buffer(buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xenvariable_handle_request(buf);
}

static void set_mtc_variable(void *buf)
{
    char16_t *mtcname = (char16_t*)mtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;

    mock_xenvariable_set_buffer(buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(mtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xenvariable_handle_request(buf);
}


/**
 * Test that using SetVariable() to save a variable
 * and subsequently calling GetVariable() to retrieve
 * that same variable results in the saved and
 * restored variable vlaues being equivalent.
 */
static void test_set_and_get(void)
{
    uint64_t status;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;
    uint32_t outdata;
    size_t outsz = sizeof(outdata);

    mock_xenvariable_set_buffer(comm_buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xenvariable_handle_request(comm_buf);
    XenGetVariable(rtcname, &guid, &attr, &outsz, (void*)&outdata);
    xenvariable_handle_request(comm_buf);

    /*
     * Assert that status is EFI_SUCCESS, and that saved and retreived
     * variables are equal
     */
    status = deserialize_xen_get_var_response(comm_buf, &attr, &outdata, &outsz);
    test(status == EFI_SUCCESS);
    test(outdata == indata);
}

/**
 * Test that SetVariable requests of size that
 * exceed the shared memory area fails with
 * EFI_OUT_OF_RESOURCES.
 */
static void test_big_set(void)
{
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = DEFAULT_ATTR;
    void *indata;
    void *tempbuf;

    /* One byte beyond than the shared memory area */
    size_t insz = (SHMEM_PAGES * PAGE_SIZE) + 1;

    /* Setup */
    indata = malloc(insz);
    memset(indata, 0, insz);
    tempbuf = malloc(insz * 16);
    mock_xenvariable_set_buffer(tempbuf);

    /* Issue and process SetVariable() */
    XenSetVariable(rtcname, &guid, attr, insz, indata);
    xenvariable_handle_request(tempbuf);

    /* Perform test assertion */
    test(getstatus(tempbuf) == EFI_OUT_OF_RESOURCES);

    /* Cleanup */
    free(indata);
    free(tempbuf);
}

/**
 * Test that a zero-length before passed to SetVariable()
 * yields a EFI_SECURITY_VIOLATION.
 */
static void test_zero_set(void)
{
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = DEFAULT_ATTR;
    size_t insz = 0;
    uint8_t indata; 

    mock_xenvariable_set_buffer(comm_buf);

    XenSetVariable(rtcname, &guid, attr, insz, &indata);
    xenvariable_handle_request(comm_buf);

    test(getstatus(comm_buf) == EFI_SECURITY_VIOLATION);
}

/**
 * Test that empty variable store returns EFI_NOT_FOUND
 * for GetNextVariableName().
 */
static void test_empty_get_next_var(void)
{
    size_t varname_sz;
    char16_t *varname;
    uint8_t guid[16];

    /* Setup */
    mock_xenvariable_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);
    varname_sz = sizeof(char16_t) * 128;
    varname = malloc(varname_sz);
    memset(varname, 0, varname_sz);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xenvariable_handle_request(comm_buf);
    test(getstatus(comm_buf) == EFI_NOT_FOUND);

    /* Cleanup */
    free(varname);
}

#define TEST_VARNAME_BUF_SZ 256

static void print_bytes(void *buf, size_t len, size_t width)
{
    uint8_t *p = buf;
    size_t i;

    for (i=0; i<len; i++)
    {
        if ( i % width == 0 )
        {
            DPRINTF("\n");
        }
        DPRINTF("0x%02x ", p[i]);
    }
    DPRINTF("\n");
}

static void show_buf(void *comm_buf)
{
    uint8_t *p = (uint8_t*)comm_buf;

    DPRINTF("comm_buf:\n");
    print_bytes(p, 64, 8);
}

/**
 * Test that variable store returns EFI_SUCCESS and returns the correct
 * variable name upon GetNextVariableName() being called after setting one
 * variable.
 */
static void test_success_get_next_var_one(void)
{
    EFI_STATUS status;
    size_t varname_sz = TEST_VARNAME_BUF_SZ;
    char16_t varname[TEST_VARNAME_BUF_SZ] = {0};
    char16_t buf[TEST_VARNAME_BUF_SZ] = {0};
    uint8_t guid[16];
    uint8_t *ptr;

    /* Setup */
    set_rtc_variable(comm_buf);
    mock_xenvariable_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xenvariable_handle_request(comm_buf);

    /* Deserialize response */
    ptr = comm_buf;
    status = unserialize_result(&ptr);
    unserialize_data(&ptr, buf, &varname_sz);

    /* Assertions */
    test(status == EFI_SUCCESS);
    test(memcmp(buf, rtcnamebytes, sizeof(rtcnamebytes)) == 0);

    XenGetNextVariableName(&varname_sz, buf, &guid);
    xenvariable_handle_request(comm_buf);

    ptr = comm_buf;
    status = unserialize_result(&ptr);
    test(status == EFI_NOT_FOUND);
}

static bool contains(char16_t buf[2][TEST_VARNAME_BUF_SZ], const char *val, size_t len)
{
    bool ret = false;
    int i;

    for (i=0; i<2; i++)
    {
        if ( memcmp(&buf[i], val, len) == 0 )
            ret = true;
    }

    return ret;
}

/**
 * Test that variable store returns EFI_SUCCESS and returns the correct
 * variable names upon GetNextVariableName() being called after setting two
 * variables.
 */
static void test_success_get_next_var_two(void)
{
    EFI_STATUS status;
    size_t varname_sz = TEST_VARNAME_BUF_SZ;
    char16_t buf[TEST_VARNAME_BUF_SZ] = {0};
    char16_t copies[2][TEST_VARNAME_BUF_SZ] = {0};
    uint8_t guid[16];
    uint8_t *ptr;
    char* p;

    /* Setup */
    set_rtc_variable(comm_buf);
    set_mtc_variable(comm_buf);
    mock_xenvariable_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    /* Store the first variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, buf, &guid);
    xenvariable_handle_request(comm_buf);

    ptr = comm_buf;
    unserialize_result(&ptr);
    unserialize_data(&ptr, &copies[0], &varname_sz);
    memcpy(buf, &copies[0], varname_sz);

    memset(comm_buf, 0, 4096);

    /* Store the second variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, buf, &guid);
    xenvariable_handle_request(comm_buf);

    ptr = comm_buf;
    unserialize_result(&ptr);
    unserialize_data(&ptr, &copies[1], &varname_sz);

    test(contains(copies, rtcnamebytes, sizeof(rtcnamebytes)));
    test(contains(copies, mtcnamebytes, sizeof(mtcnamebytes)));

    /* Store the second variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, &copies[1], &guid);
    xenvariable_handle_request(comm_buf);

    ptr = comm_buf;
    status = unserialize_result(&ptr);
    test(status == EFI_NOT_FOUND);
}

static void test_get_next_var_buf_too_small(void)
{
    EFI_STATUS status;
    size_t varname_sz = 2;
    char16_t varname[2] = {0};
    uint8_t guid[16] = {0};
    uint8_t *ptr;
    size_t newsz;

    /* Setup */
    set_rtc_variable(comm_buf);
    mock_xenvariable_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xenvariable_handle_request(comm_buf);

    /* Deserialize response */
    ptr = comm_buf;
    status = unserialize_result(&ptr);
    newsz = unserialize_uintn(&ptr);

    /* Assertions */
    test(status == EFI_BUFFER_TOO_SMALL);
    test(newsz == 6);
}

static void test_runtime_access_attr(void)
{
    uint64_t status;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = EFI_VARIABLE_NON_VOLATILE;
    uint32_t indata = 0xdeadbeef;
    uint32_t outdata;
    size_t outsz = sizeof(outdata);

    mock_xenvariable_set_buffer(comm_buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xenvariable_handle_request(comm_buf);
    XenGetVariable(rtcname, &guid, &attr, &outsz, (void*)&outdata);
    xenvariable_handle_request(comm_buf);

    /*
     * Assert that status is EFI_SUCCESS, and that saved and retreived
     * variables are equal
     */
    status = deserialize_xen_get_var_response(comm_buf, &attr, &outdata, &outsz);
    test(status == EFI_NOT_FOUND);
}

void test_xenvariable(void)
{
    DO_TEST(test_nonexistent_variable_returns_not_found);
    DO_TEST(test_set_and_get);
    DO_TEST(test_big_set);
    DO_TEST(test_zero_set);
    DO_TEST(test_empty_get_next_var);
    DO_TEST(test_success_get_next_var_one);
    DO_TEST(test_success_get_next_var_two);
    DO_TEST(test_get_next_var_buf_too_small);
    DO_TEST(test_runtime_access_attr);
}
