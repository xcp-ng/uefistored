#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "munit/munit.h"

#include "storage.h"
#include "common.h"
#include "log.h"
#include "mock/XenVariable.h"
#include "serializer.h"
#include "test_common.h"
#include "uefi/types.h"
#include "xen_variable_server.h"

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

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

static MunitResult
test_nonexistent_variable_returns_not_found(const MunitParameter *params, void *d)
{
    char16_t *rtcname = (char16_t *)rtcnamebytes;
    EFI_GUID guid = DEFAULT_GUID;
    uint32_t attr;
    uint64_t data;
    uint64_t datasize = sizeof(data);

    comm_buf = comm_buf_phys;
    mock_xen_variable_server_set_buffer(comm_buf);

    guid.Data1 = 0xde;

    /* Build a GetVariable() command */
    XenGetVariable(rtcname, &guid, &attr, &datasize, (void *)&data);

    /* Handle the command */
    xen_variable_server_handle_request(comm_buf);

    // xen_variable_server_handle_request(comm_buf);
    munit_assert(getstatus(comm_buf) == EFI_NOT_FOUND);

    return MUNIT_OK;
}

static EFI_STATUS deserialize_xen_get_var_response(void *buf,
                                                   uint32_t *Attributes,
                                                   void *Data, size_t *DataSize)
{
    uint32_t attr;
    const uint8_t *ptr = buf;
    EFI_STATUS status;

    status = unserialize_result(&ptr);
    switch (status) {
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
    char16_t *rtcname = (char16_t *)rtcnamebytes;
    EFI_GUID guid = DEFAULT_GUID;
    uint32_t indata = 0xdeadbeef;

    mock_xen_variable_server_set_buffer(buf);

    XenSetVariable(rtcname, &guid, DEFAULT_ATTR, sizeof(indata),
                   (void *)&indata);
    xen_variable_server_handle_request(buf);
}

static void set_mtc_variable(void *buf)
{
    char16_t *mtcname = (char16_t *)mtcnamebytes;
    EFI_GUID guid = DEFAULT_GUID;
    uint32_t indata = 0xdeadbeef;

    mock_xen_variable_server_set_buffer(buf);

    XenSetVariable(mtcname, &guid, DEFAULT_ATTR, sizeof(indata),
                   (void *)&indata);
    xen_variable_server_handle_request(buf);
}

/**
 * Test that using SetVariable() to save a variable
 * and subsequently calling GetVariable() to retrieve
 * that same variable results in the saved and
 * restored variables being equivalent.
 */
static MunitResult test_set_and_get(const MunitParameter *params, void *data)
{
    uint64_t status;
    char16_t *rtcname = (char16_t *)rtcnamebytes;
    EFI_GUID guid = DEFAULT_GUID;
    uint32_t attr = DEFAULT_ATTR;
    uint32_t indata = 0xdeadbeef;
    uint32_t outdata;
    size_t outsz = sizeof(outdata);

    mock_xen_variable_server_set_buffer(comm_buf);

    /* Perform SetVariable() and then GetVariable() */
    XenSetVariable(rtcname, &guid, attr, sizeof(indata), (void *)&indata);
    xen_variable_server_handle_request(comm_buf);
    XenGetVariable(rtcname, &guid, &attr, &outsz, (void *)&outdata);
    xen_variable_server_handle_request(comm_buf);

    /*
     * Assert that status is EFI_SUCCESS, and that saved and retreived
     * variables are equal
     */
    status =
            deserialize_xen_get_var_response(comm_buf, &attr, &outdata, &outsz);
    munit_assert(status == EFI_SUCCESS);
    munit_assert(outdata == indata);

    return MUNIT_OK;
}

/**
 * Test that SetVariable requests of size that
 * exceed the shared memory area fails with
 * EFI_OUT_OF_RESOURCES.
 */
static MunitResult test_big_set(const MunitParameter *params, void *data)
{
    char16_t *rtcname = (char16_t *)rtcnamebytes;
    EFI_GUID guid = DEFAULT_GUID;
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
    XenSetVariable(rtcname, &guid, DEFAULT_ATTR, insz, indata);
    xen_variable_server_handle_request(tempbuf);

    /* Perform test assertion */
    munit_assert(getstatus(tempbuf) == EFI_OUT_OF_RESOURCES);

    /* Cleanup */
    free(indata);
    free(tempbuf);

    return MUNIT_OK;
}

/**
 * Test that a zero-length var before passed to SetVariable()
 * yields EFI_SUCCESS.
 *
 * TODO: check that the variable was cleared.
 */
static MunitResult test_zero_set(const MunitParameter *params, void *data)
{
    char16_t *rtcname = (char16_t *)rtcnamebytes;
    EFI_GUID guid = DEFAULT_GUID;
    uint32_t attr = DEFAULT_ATTR;
    size_t insz = 0;
    uint8_t indata;

    mock_xen_variable_server_set_buffer(comm_buf);
    set_rtc_variable(comm_buf);

    XenSetVariable(rtcname, &guid, attr, insz, &indata);
    xen_variable_server_handle_request(comm_buf);

    munit_assert(getstatus(comm_buf) == EFI_SUCCESS);

    return MUNIT_OK;
}

/**
 * Test that empty variable store returns EFI_NOT_FOUND
 * for GetNextVariableName().
 */
static MunitResult test_empty_get_next_var(const MunitParameter *params, void *data)
{
    size_t varname_sz;
    char16_t *varname;
    EFI_GUID guid = DEFAULT_GUID;

    /* Setup */
    mock_xen_variable_server_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);
    varname_sz = 128;
    varname = malloc(varname_sz);
    memset(varname, 0, varname_sz);

    /* Call GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, varname, &guid);
    xen_variable_server_handle_request(comm_buf);
    munit_assert(getstatus(comm_buf) == EFI_NOT_FOUND);

    /* Cleanup */
    free(varname);

    return MUNIT_OK;
}

#define TEST_VARNAME_BUF_SZ 256

static MunitResult test_success_get_next_var_one(const MunitParameter *params, void *data)
{
    EFI_STATUS status;
    size_t varname_sz = TEST_VARNAME_BUF_SZ;
    char16_t varname[TEST_VARNAME_BUF_SZ] = { 0 };
    char16_t buf[TEST_VARNAME_BUF_SZ] = { 0 };
    EFI_GUID guid = DEFAULT_GUID;
    const uint8_t *ptr;

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
    munit_assert(status == EFI_SUCCESS);
    munit_assert(memcmp(buf, rtcnamebytes, sizeof(rtcnamebytes)) == 0);

    /* Do second call */
    XenGetNextVariableName(&varname_sz, buf, &guid);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    status = unserialize_result(&ptr);
    munit_assert(status == EFI_NOT_FOUND);

    return MUNIT_OK;
}

static bool contains(char16_t buf[2][TEST_VARNAME_BUF_SZ], void *val,
                     size_t len)
{
    bool ret = false;
    int i;

    for (i = 0; i < 2; i++) {
        if (memcmp(&buf[i], val, len) == 0)
            ret = true;
    }

    return ret;
}

/**
 * Test that variable store returns EFI_SUCCESS and returns the correct
 * variable names upon GetNextVariableName() being called after setting two
 * variables.
 */
static MunitResult test_success_get_next_var_two(const MunitParameter *params, void *data)
{
    EFI_STATUS status;
    size_t varname_sz = TEST_VARNAME_BUF_SZ;
    char16_t buf[TEST_VARNAME_BUF_SZ] = { 0 };
    char16_t copies[2][TEST_VARNAME_BUF_SZ] = { { 0 } };
    EFI_GUID guid = DEFAULT_GUID;
    const uint8_t *ptr;

    /* Setup */
    mock_xen_variable_server_set_buffer(comm_buf);
    memset(comm_buf, 0, 4096);

    set_rtc_variable(comm_buf);
    set_mtc_variable(comm_buf);

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

    munit_assert(contains(copies, rtcnamebytes, sizeof(rtcnamebytes)));
    munit_assert(contains(copies, mtcnamebytes, sizeof(mtcnamebytes)));

    /* Store the second variable from GetNextVariableName() */
    XenGetNextVariableName(&varname_sz, (char16_t *)&copies[1], &guid);
    xen_variable_server_handle_request(comm_buf);

    ptr = comm_buf;
    status = unserialize_result(&ptr);
    munit_assert(status == EFI_NOT_FOUND);

    return MUNIT_OK;
}

static MunitResult
test_get_next_var_buf_too_small(const MunitParameter *params, void *data)
{
    EFI_STATUS status;
    size_t varname_sz = 2;
    char16_t varname[2] = { 0 };
    EFI_GUID guid = DEFAULT_GUID;
    const uint8_t *ptr;
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
    munit_assert(status == EFI_BUFFER_TOO_SMALL);
    munit_assert(newsz == strsize16(rtcnamebytes) + 2);

    return MUNIT_OK;
}

/**
 * Test QueryVariableInfo bad input attributes are rejected.
 *
 * All attributes should have the same contstraints;
 */
static MunitResult
test_query_variable_info_bad_attrs(const MunitParameter *params, void *data)
{
    const uint8_t *ptr;
    uint64_t max_storage_size, remaining_storage_size, max_variable_size;

    mock_xen_variable_server_set_buffer(comm_buf);

    XenQueryVariableInfo(
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_HARDWARE_ERROR_RECORD,
            &max_storage_size, &remaining_storage_size, &max_variable_size);
    xen_variable_server_handle_request(comm_buf);


    ptr = comm_buf;
    munit_assert(unserialize_result(&ptr) == EFI_SUCCESS);

    XenQueryVariableInfo(
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            &max_storage_size, &remaining_storage_size, &max_variable_size);
    xen_variable_server_handle_request(comm_buf);
    ptr = comm_buf;
    munit_assert(unserialize_result(&ptr) == EFI_SUCCESS);

    XenQueryVariableInfo(EFI_VARIABLE_RUNTIME_ACCESS |
                                 EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
                         &max_storage_size, &remaining_storage_size,
                         &max_variable_size);
    xen_variable_server_handle_request(comm_buf);
    ptr = comm_buf;
    munit_assert(unserialize_result(&ptr) == EFI_INVALID_PARAMETER);

    return MUNIT_OK;
}

/**
 * Test that valid attrs is correct.
 */
static MunitResult
test_valid_attrs(const MunitParameter *params, void *data)
{
    /* We don't support authenticated writes yet */
    munit_assert(evaluate_attrs(EFI_VARIABLE_RUNTIME_ACCESS |
                     EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != EFI_SUCCESS);

    /* We don't support hardware error record yet  */
    munit_assert(evaluate_attrs(EFI_VARIABLE_RUNTIME_ACCESS |
                     EFI_VARIABLE_HARDWARE_ERROR_RECORD) != EFI_SUCCESS);

    /* Runetime accesss requires boot access */
    munit_assert(evaluate_attrs(EFI_VARIABLE_RUNTIME_ACCESS &
                     ~EFI_VARIABLE_BOOTSERVICE_ACCESS) != EFI_SUCCESS);

    return MUNIT_OK;
}

/**
 * Test QueryVariableInfo functions correctly.
 *
 * All attributes should have the same contstraints;
 */
static MunitResult
test_query_variable_info(const MunitParameter *params, void *data)
{
    const uint8_t *ptr;
    uint32_t attrs;
    uint64_t max_storage_size, remaining_storage_size, max_variable_size;

    mock_xen_variable_server_set_buffer(comm_buf);

    attrs = 1 << 31;

    while (attrs) {
        if (evaluate_attrs(attrs) != EFI_SUCCESS) {
            attrs >>= 1;
            continue;
        }

        /* serialize message */
        XenQueryVariableInfo(attrs, &max_storage_size, &remaining_storage_size,
                             &max_variable_size);

        /* send message */
        xen_variable_server_handle_request(comm_buf);

        /* parse response */
        ptr = comm_buf;
        unserialize_result(&ptr);

        max_storage_size = unserialize_uint64(&ptr);
        remaining_storage_size = unserialize_uint64(&ptr);
        max_variable_size = unserialize_uint64(&ptr);

        munit_assert_long(max_storage_size, =, MAX_STORAGE_SIZE);
        munit_assert_long(remaining_storage_size, =, MAX_STORAGE_SIZE);
        munit_assert_long(max_variable_size, =, MAX_VARIABLE_SIZE);

        attrs >>= 1;
    }

    return MUNIT_OK;
}

static void tear_down(void* fixture)
{
    storage_destroy();
}

#define DEFINE_TEST(test_func)                  \
    { (char*) #test_func, test_func,            \
        NULL,               \
        tear_down,          \
        MUNIT_SUITE_OPTION_NONE, NULL }

MunitTest xen_variable_server_tests[] = {
    DEFINE_TEST(test_nonexistent_variable_returns_not_found),
    DEFINE_TEST(test_set_and_get),
    DEFINE_TEST(test_big_set),
    DEFINE_TEST(test_zero_set),
    DEFINE_TEST(test_empty_get_next_var),
    DEFINE_TEST(test_success_get_next_var_one),
    DEFINE_TEST(test_success_get_next_var_two),
    DEFINE_TEST(test_get_next_var_buf_too_small),
    DEFINE_TEST(test_query_variable_info),
    DEFINE_TEST(test_query_variable_info_bad_attrs),
    DEFINE_TEST(test_valid_attrs),
    { 0 }
};
