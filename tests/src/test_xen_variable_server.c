#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "storage.h"
#include "common.h"
#include "log.h"
#include "mock/XenVariable.h"
#include "serializer.h"
#include "test_common.h"
#include "UefiMultiPhase.h"
#include "uefitypes.h"
#include "xen_variable_server.h"

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static void pre_test(void)
{
    storage_init();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

static void post_test(void)
{
    storage_deinit();
    storage_destroy();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

/* Test Data */
UTF16 rtcnamebytes[] = {
    'R',
    'T',
    'C',
     '\0',
};

UTF16 mtcnamebytes[] = {
    'M',
    'T',
    'C',
     '\0',
};

static inline uint64_t getstatus(void *p)
{
    uint64_t ret;

    memcpy(&ret, p, sizeof(ret));

    return ret;
}

static void test_nonexistent_variable_returns_not_found(void)
{
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    EFI_GUID guid;
    uint32_t attr;
    uint64_t data;
    uint64_t datasize = sizeof(data);

    comm_buf = comm_buf_phys;
    mock_xen_variable_server_set_buffer(comm_buf);

    guid.Data1 = 0xde;

    /* Build a GetVariable() command */
    XenGetVariable(rtcname, &guid, &attr, &datasize, (void*)&data);

    /* Handle the command */
    xen_variable_server_handle_request(comm_buf);

   // xen_variable_server_handle_request(comm_buf);
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
        unserialize_data(&ptr, Data, *DataSize);
        break;
    case EFI_BUFFER_TOO_SMALL:
        *DataSize = unserialize_uintn(&ptr);
        break;
    default:
        break;
    }

    return status;
}

/* Helpers */
static void set_rtc_variable(void *buf)
{
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;

    mock_xen_variable_server_set_buffer(buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xen_variable_server_handle_request(buf);
}

static void set_mtc_variable(void *buf)
{
    char16_t *mtcname = (char16_t*)mtcnamebytes;
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;

    mock_xen_variable_server_set_buffer(buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(mtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xen_variable_server_handle_request(buf);
}


/**
 * Test that using SetVariable() to save a variable
 * and subsequently calling GetVariable() to retrieve
 * that same variable results in the saved and
 * restored variables being equivalent.
 */
static void test_set_and_get(void)
{
    uint64_t status;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;
    uint32_t outdata;
    size_t outsz = sizeof(outdata);

    mock_xen_variable_server_set_buffer(comm_buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xen_variable_server_handle_request(comm_buf);
    XenGetVariable(rtcname, &guid, &attr, &outsz, (void*)&outdata);
    xen_variable_server_handle_request(comm_buf);

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
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTR;
    void *indata;
    void *tempbuf;

    /* One byte beyond than the shared memory area */
    size_t insz = (SHMEM_PAGES * PAGE_SIZE) + 1;

    /* Setup */
    indata = malloc(insz);
    memset(indata, 0, insz);
    tempbuf = malloc(insz * 16);
    mock_xen_variable_server_set_buffer(tempbuf);

    /* Issue and process SetVariable() */
    XenSetVariable(rtcname, &guid, attr, insz, indata);
    xen_variable_server_handle_request(tempbuf);

    /* Perform test assertion */
    test(getstatus(tempbuf) == EFI_OUT_OF_RESOURCES);

    /* Cleanup */
    free(indata);
    free(tempbuf);
}

/**
 * Test that a zero-length var before passed to SetVariable()
 * yields EFI_SUCCESS.
 *
 * TODO: check that the variable was cleared.
 */
static void test_zero_set(void)
{
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTR;
    size_t insz = 0;
    uint8_t indata; 

    mock_xen_variable_server_set_buffer(comm_buf);

    XenSetVariable(rtcname, &guid, attr, insz, &indata);
    xen_variable_server_handle_request(comm_buf);

    test(getstatus(comm_buf) == EFI_SUCCESS);
}

/**
 * Test that empty variable store returns EFI_NOT_FOUND
 * for GetNextVariableName().
 */
static void test_empty_get_next_var(void)
{
    size_t varname_sz;
    char16_t *varname;
    EFI_GUID guid;

    /* Setup */
    mock_xen_variable_server_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);
    varname_sz = sizeof(char16_t) * 128;
    varname = malloc(varname_sz);
    memset(varname, 0, varname_sz);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xen_variable_server_handle_request(comm_buf);
    test(getstatus(comm_buf) == EFI_NOT_FOUND);

    /* Cleanup */
    free(varname);
}

#define TEST_VARNAME_BUF_SZ 256

static void test_success_get_next_var_one(void)
{
    EFI_STATUS status;
    size_t varname_sz = TEST_VARNAME_BUF_SZ;
    char16_t varname[TEST_VARNAME_BUF_SZ] = {0};
    char16_t buf[TEST_VARNAME_BUF_SZ] = {0};
    EFI_GUID guid;
    uint8_t *ptr;

    /* Setup */
    set_rtc_variable(comm_buf);
    mock_xen_variable_server_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xen_variable_server_handle_request(comm_buf);

    /* Deserialize response */
    ptr = comm_buf;
    status = unserialize_result(&ptr);
    unserialize_data(&ptr, buf, varname_sz);

    /* Assertions */
    test(status == EFI_SUCCESS);
    test(memcmp(buf, rtcnamebytes, sizeof(rtcnamebytes)) == 0);

    XenGetNextVariableName(&varname_sz, buf, &guid);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    status = unserialize_result(&ptr);
    printf("status=0x%02lx\n", status);
    printf("EFI_NOT_FOUND=0x%02lx\n", EFI_NOT_FOUND);
    test(status == EFI_NOT_FOUND);
}

static bool contains(char16_t buf[2][TEST_VARNAME_BUF_SZ], void *val, size_t len)
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
    EFI_GUID guid;
    uint8_t *ptr;

    /* Setup */
    set_rtc_variable(comm_buf);
    set_mtc_variable(comm_buf);
    mock_xen_variable_server_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    /* Store the first variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, buf, &guid);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    unserialize_result(&ptr);
    unserialize_data(&ptr, &copies[0], varname_sz);
    memcpy(buf, &copies[0], varname_sz);

    memset(comm_buf, 0, 4096);

    /* Store the second variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, buf, &guid);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    unserialize_result(&ptr);
    unserialize_data(&ptr, &copies[1], varname_sz);

    test(contains(copies, rtcnamebytes, sizeof(rtcnamebytes)));
    test(contains(copies, mtcnamebytes, sizeof(mtcnamebytes)));

    /* Store the second variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, (char16_t*)&copies[1], &guid);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    status = unserialize_result(&ptr);
    test(status == EFI_NOT_FOUND);
}

static void test_get_next_var_buf_too_small(void)
{
    EFI_STATUS status;
    size_t varname_sz = 2;
    char16_t varname[2] = {0};
    EFI_GUID guid;
    uint8_t *ptr;
    size_t newsz;

    /* Setup */
    set_rtc_variable(comm_buf);
    mock_xen_variable_server_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xen_variable_server_handle_request(comm_buf);

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
    EFI_GUID guid;
    uint32_t attr = EFI_VARIABLE_NON_VOLATILE;
    uint32_t indata = 0xdeadbeef;
    uint32_t outdata;
    size_t outsz = sizeof(outdata);

    mock_xen_variable_server_set_buffer(comm_buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void*)&indata);
    xen_variable_server_handle_request(comm_buf);
    XenGetVariable(rtcname, &guid, &attr, &outsz, (void*)&outdata);
    xen_variable_server_handle_request(comm_buf);

    /*
     * Assert that status is EFI_SUCCESS, and that saved and retreived
     * variables are equal
     */
    status = deserialize_xen_get_var_response(comm_buf, &attr, &outdata, &outsz);
    test(status == EFI_NOT_FOUND);
}

/**
 * Test QueryVariableInfo bad input attributes are rejected.
 *
 * All attributes should have the same contstraints;
 */
static void test_query_variable_info_bad_attrs(void)
{
    uint8_t *ptr;
    uint64_t max_storage_size, remaining_storage_size, max_variable_size;

    mock_xen_variable_server_set_buffer(comm_buf);

    XenQueryVariableInfo(EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | \
            EFI_VARIABLE_HARDWARE_ERROR_RECORD, &max_storage_size, &remaining_storage_size, &max_variable_size);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    test(unserialize_result(&ptr) == EFI_UNSUPPORTED);

    XenQueryVariableInfo(EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            &max_storage_size, &remaining_storage_size, &max_variable_size);
    xen_variable_server_handle_request(comm_buf);
    ptr = comm_buf;
    test(unserialize_result(&ptr) == EFI_SUCCESS);

    XenQueryVariableInfo(EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
            &max_storage_size, &remaining_storage_size, &max_variable_size);
    xen_variable_server_handle_request(comm_buf);
    ptr = comm_buf;
    test(unserialize_result(&ptr) == EFI_UNSUPPORTED);
}

/**
 * Test that valid attrs is correct.
 */
static void test_valid_attrs(void)
{
    /* We don't support authenticated writes yet */
    test(valid_attrs(EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) == false);

    /* We don't support hardware error record yet  */
    test(valid_attrs(EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_HARDWARE_ERROR_RECORD) == false);

    /* Runetime accesss requires boot access */
    test(valid_attrs(EFI_VARIABLE_RUNTIME_ACCESS & ~EFI_VARIABLE_BOOTSERVICE_ACCESS) == false);
}


/**
 * Test QueryVariableInfo functions correctly.
 *
 * All attributes should have the same contstraints;
 */
static void test_query_variable_info(void)
{
    uint8_t *ptr;
    uint32_t attrs;
    uint64_t max_storage_size, remaining_storage_size, max_variable_size;

    mock_xen_variable_server_set_buffer(comm_buf);

    attrs = 1<<31;

    while ( attrs )
    {
        if ( !valid_attrs(attrs) )
        {
            attrs >>= 1;
            continue;
        }

        /* serialize message */
        XenQueryVariableInfo(attrs, &max_storage_size, &remaining_storage_size, &max_variable_size);

        /* send message */
        xen_variable_server_handle_request(comm_buf);

        /* parse response */
        ptr = comm_buf;
        EFI_STATUS status = unserialize_result(&ptr);

        printf("status=0x%02lx\n", status);

        max_storage_size = unserialize_uint64(&ptr);
        remaining_storage_size = unserialize_uint64(&ptr);
        max_variable_size = unserialize_uint64(&ptr);

        printf("attrs=0x%02x\n", attrs);
        test_eq_int64(max_storage_size, MAX_STORAGE_SIZE);
        test_eq_int64(remaining_storage_size, MAX_STORAGE_SIZE);
        test_eq_int64(max_variable_size, MAX_VARIABLE_SIZE);

        attrs >>= 1;
    }
}

void test_xen_variable_server(void)
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
    DO_TEST(test_query_variable_info);
    DO_TEST(test_query_variable_info_bad_attrs);
    DO_TEST(test_valid_attrs);
}
