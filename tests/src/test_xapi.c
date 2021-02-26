#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "munit/munit.h"

#include "storage.h"
#include "common.h"
#include "log.h"
#include "test_common.h"
#include "test_xapi.h"
#include "xapi.h"
#include "mock/XenVariable.h"
#include "xen_variable_server.h"

#define TEST_PT_SIZE 512

EFI_GUID default_guid = DEFAULT_GUID;

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static UTF16 v1[] = { 'B', 'C', '\0' };
static UTF16 v2[] = { 'Y', 'Z', '\0' };

static char *D1 = "WORLD!";
static char *D2 = "bar";

static size_t v1_len;
static size_t d1_len;
static size_t v2_len;
static size_t d2_len;
static size_t blocksz;

static variable_t vars[2];

#define BUFFER_MAX (4096*4)
#define VAR_MAX 512

char *bytes_to_base64(uint8_t *buffer, size_t length);
int base64_to_bytes(uint8_t *plaintext, size_t n, char *encoded,
                    size_t encoded_size);

MunitResult test_base64(const MunitParameter *params, void* data)
{
    int i, var_num;
    int ret, sz;
    uint8_t buffer[BUFFER_MAX] = {0};
    char base64[BUFFER_MAX] = {0};
    uint8_t serialized[BUFFER_MAX] = {0};
    uint8_t *ptr;
    variable_t vars[VAR_MAX];
    FILE *fd;

    memset(vars, 0, sizeof(vars));

    fd = fopen("data/simple-db.b64", "r");
    munit_assert(fd != NULL);

    sz = fread(base64, 1, BUFFER_MAX, fd);
    fclose(fd);

    ret = base64_to_bytes(buffer, BUFFER_MAX, base64, sz);
    munit_assert(ret >= 0);

    var_num = ret = from_bytes_to_vars(vars, VAR_MAX, buffer, ret);
    munit_assert(ret >= 0);

    ptr = serialized;
    ret = serialize_variable_list(&ptr, BUFFER_MAX, vars, ret);

    munit_assert(ret >= 0);
    munit_assert_int(memcmp(serialized, buffer, BUFFER_MAX), ==, 0);

    for (i=0; i<var_num; i++) {
        variable_destroy_noalloc(&vars[i]);
    }

    return MUNIT_OK;
}

static MunitResult test_bytes(const MunitParameter *params, void* data)
{
    uint8_t bytes[4096] = { 0 };
    uint8_t *p = (uint8_t *)bytes;
    variable_t orig = {{ 0 }};
    variable_t var = {{ 0 }};

    /* Setup */
    variable_create_noalloc(&orig, L"FOO", sizeof(L"FOO"), (uint8_t *)L"BAR",
            strsize16(L"BAR"), &default_guid, DEFAULT_ATTR, NULL, NULL);

    serialize_variable_list(&p, TEST_PT_SIZE, &orig, 1);
    from_bytes_to_vars(&var, 1, bytes, 4096);

    munit_assert(variable_eq(&orig, &var));
    variable_destroy_noalloc(&orig);
    variable_destroy_noalloc(&var);

    return MUNIT_OK;
}

static MunitResult test_var_copy(const MunitParameter *params, void *data)
{
    uint8_t buf[4096] = { 0 };
    uint8_t *p;
    const uint8_t *unserial_ptr;
    variable_t orig = {{ 0 }};
    variable_t *var = NULL;

    /* Setup */
    variable_create_noalloc(&orig, L"FOO", sizeof(L"FOO"), (uint8_t *)L"BAR",
            strsize16(L"BAR"), &default_guid, DEFAULT_ATTR, NULL, NULL);

    /* Do the work */
    p = buf;
    serialize_var(&p, &orig);
    unserial_ptr = buf;
    var = variable_create_unserialize(&unserial_ptr);

    /* Do the test */
    munit_assert(variable_eq(var, &orig));

    variable_destroy(var);
    variable_destroy_noalloc(&orig);

    return MUNIT_OK;
}

/**
 * Passes if serializing a list of size 1 and then deserializig it results in
 * the same list of size 1.
 */
static MunitResult test_list_serialization(const MunitParameter *params, void *data)
{
    char *base64;
    uint8_t buf[4096] = { 0 };
    uint8_t *p = (uint8_t *)buf;
    uint8_t bytes[4096] = { 0 };
    variable_t *orig;
    variable_t var = {{ 0 }};

    /* Setup */
    orig = variable_create(L"FOO", sizeof(L"FOO"), (uint8_t *)L"BAR",
            strsize16(L"BAR"), &default_guid, DEFAULT_ATTR);

    /* Convert variable into bytes, and then bytes into base64 */
    serialize_variable_list(&p, 4096, orig, 1);
    base64 = bytes_to_base64(buf, list_size(orig, 1));

    /* Convert base64 to bytes, then bytes back to variable */
    base64_to_bytes(bytes, 4096, base64, strlen(base64));
    from_bytes_to_vars(&var, 1, bytes, 4096);

    /* Assert the original variable and the decoded variable are equal */
    munit_assert(variable_eq(&var, orig));

    /* Cleanup */
    free(base64);
    variable_destroy(orig);
    variable_destroy_noalloc(&var);

    return MUNIT_OK;
}

static void xapi_tear_down(void *fixture)
{
    storage_destroy();
    variable_destroy_noalloc(&vars[0]);
    variable_destroy_noalloc(&vars[1]);
}

static void *xapi_setup(const MunitParameter params[], void* user_data)
{
    v1_len = strsize16((char16_t *)v1) + sizeof(UTF16);
    d1_len = strlen(D1);
    v2_len = strsize16((char16_t *)v2) + sizeof(UTF16);
    d2_len = strlen(D2);

    blocksz = v1_len + sizeof(v1_len) + d1_len + sizeof(d1_len) + v2_len +
              sizeof(v2_len) + d2_len + sizeof(d2_len);

    memset(vars, 0, sizeof(vars));

    variable_create_noalloc(&vars[0], v1, v1_len, (uint8_t *)D1, d1_len,
                            &default_guid, DEFAULT_ATTR, NULL, NULL);

    variable_create_noalloc(&vars[1], v2, v2_len, (uint8_t *)D2, d2_len,
                            &default_guid, DEFAULT_ATTR, NULL, NULL);

    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
    return NULL;
}

#define DEFINE_TEST(test_func)                                          \
    { (char*) #test_func, test_func,          \
        xapi_setup, xapi_tear_down, MUNIT_SUITE_OPTION_NONE, NULL }

MunitTest xapi_tests[] = {
    DEFINE_TEST(test_var_copy),
    DEFINE_TEST(test_bytes),
    DEFINE_TEST(test_list_serialization),
    { (char*)"test_base64", test_base64,
        NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
