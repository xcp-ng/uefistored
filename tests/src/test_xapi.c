#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "munit/munit.h"

#include "storage.h"
#include "data/bigbase64.h"
#include "data/bigrequest.h"
#include "data/bigrequest2.h"
#include "common.h"
#include "log.h"
#include "test_common.h"
#include "test_xapi.h"
#include "xapi.h"
#include "mock/XenVariable.h"
#include "xen_variable_server.h"

#define TEST_PT_SIZE 512

EFI_GUID default_guid = DEFAULT_GUID;

static char *BIG_BASE64 = BIG_BASE64_STR;
static char *BIG_BASE64_XML = BIG_BASE64_XML_STR;

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static UTF16 v1[] = { 'B', 'C', '\0' };
static UTF16 v2[] = { 'Y', 'Z', '\0' };
static const UTF16 FOO[] = { 'F', 'O', 'O', '\0' };
static const UTF16 BAR[] = { 'B', 'A', 'R', '\0' };

static char *D1 = "WORLD!";
static char *D2 = "bar";

static size_t v1_len;
static size_t d1_len;
static size_t v2_len;
static size_t d2_len;
static size_t blocksz;

static variable_t vars[2];

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

void test_xapi_set_efi_vars(void)
{
    char readbuf[4096] = { 0 };
    int fd;
    variable_t *var;
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTR;

    var = &vars[0];
    mock_xen_variable_server_set_buffer(comm_buf);
    XenSetVariable(var->name, &guid, attr, var->datasz, (void *)var->data);
    xen_variable_server_handle_request(comm_buf);

    var = &vars[1];
    mock_xen_variable_server_set_buffer(comm_buf);
    XenSetVariable(var->name, &guid, attr, var->datasz, (void *)var->data);
    xen_variable_server_handle_request(comm_buf);

    xapi_set_efi_vars();

    fd = open("./mock_socket", O_RDWR | O_EXCL, S_IRWXU);

    munit_assert(fd > 0);
    munit_assert(read(fd, readbuf, 4096) >= 0);
    munit_assert(strstr(readbuf,
                "BAAAAAAAAABCAEMABgAAAAAAAABXT1JMRCEEAAAAAAAAAFkAWgADAAAAAAAAAGJh") !=
         NULL);

    remove("./mock_socket");
}

static void test_bytes(void)
{
    uint8_t bytes[4096] = { 0 };
    uint8_t *p = (uint8_t *)bytes;
    variable_t orig = {{ 0 }};
    variable_t var = {{ 0 }};

    /* Setup */
    variable_create_noalloc(&orig, FOO, (uint8_t *)BAR, strsize16(BAR),
                            &default_guid, DEFAULT_ATTR, NULL);

    serialize_variable_list(&p, TEST_PT_SIZE, &orig, 1);
    from_bytes_to_vars(&var, 1, bytes, TEST_PT_SIZE);

    munit_assert(variable_eq(&orig, &var));
    variable_destroy_noalloc(&orig);
    variable_destroy_noalloc(&var);
}

static void test_var_copy(void)
{
    uint8_t buf[4096] = { 0 };
    uint8_t *p;
    const uint8_t *unserial_ptr;
    variable_t orig = {{ 0 }};
    variable_t *var = NULL;

    /* Setup */
    variable_create_noalloc(&orig, FOO, (uint8_t *)BAR, strsize16(BAR),
                            &default_guid, DEFAULT_ATTR, NULL);

    /* Do the work */
    p = buf;
    serialize_var(&p, &orig);
    unserial_ptr = buf;
    var = variable_create_unserialize(&unserial_ptr);

    /* Do the test */
    munit_assert(variable_eq(var, &orig));

    variable_destroy(var);
    variable_destroy_noalloc(&orig);
}

/**
 * Passes if serializing a list of size 1 and then deserializig it results in
 * the same list of size 1.
 */
void test_xapi_base64(void)
{
    int sz;
    char *base64;
    uint8_t buf[4096] = { 0 };
    uint8_t *p = (uint8_t *)buf;
    uint8_t bytes[4096] = { 0 };
    variable_t *orig;
    variable_t var = {{ 0 }};

    /* Setup */
    orig = variable_create(FOO, (uint8_t *)BAR, strsize16(BAR), &default_guid,
                           DEFAULT_ATTR);

    /* Convert variable into bytes, and then bytes into base64 */
    serialize_variable_list(&p, 4096, orig, 1);
    base64 = bytes_to_base64(buf, list_size(orig, 1));

    /* Convert base64 to bytes, then bytes back to variable */
    sz = base64_to_bytes(bytes, 4096, base64, strlen(base64));
    from_bytes_to_vars(&var, 1, bytes, sz);

    /* Assert the original variable and the decoded variable are equal */
    munit_assert(variable_eq(&var, orig));

    /* Cleanup */
    free(base64);
    variable_destroy(orig);
    variable_destroy_noalloc(&var);
}

#define VARCNT 2
#define BUFSZ (4096 * 2)

void test_xapi_base64_big(void)
{
    bool has_bootorder = false, has_conout = false;
    int ret;
    int i;
    uint8_t pt[4096 * 4];
    variable_t vars[256];
    memset(vars, 0, sizeof(vars));

    ret = base64_to_bytes(pt, 4096 * 4, BIG_BASE64, strlen(BIG_BASE64));
    munit_assert(ret > 0);

    ret = from_bytes_to_vars(vars, 256, pt, ret);

    for (i = 0; i < ret; i++) {
        char ascii[512];

        uc2_ascii(vars[i].name, ascii, 512);

        if (strcmp(ascii, "BootOrder") == 0)
            has_bootorder = true;
        else if (strcmp(ascii, "ConOut") == 0)
            has_conout = true;

        variable_destroy_noalloc(&vars[i]);
    }

    munit_assert(has_bootorder);
    munit_assert(has_conout);
}

void test_xapi_base64_big_xml(void)
{
    bool has_bootorder = false, has_conout = false;
    int ret;
    int i;
    char base64[4096 * 4];
    uint8_t pt[4096 * 4];
    variable_t vars[256];

    memset(vars, 0, sizeof(vars));

    ret = base64_from_response_body(base64, 4096 * 4, BIG_BASE64_XML);
    munit_assert(ret == 0);

    ret = base64_to_bytes(pt, 4096 * 4, base64, strlen(base64));
    munit_assert(ret > 0);

    ret = from_bytes_to_vars(vars, 256, pt, ret);

    for (i = 0; i < ret; i++) {
        char ascii[512];
        uc2_ascii(vars[i].name, ascii, 512);

        if (strcmp(ascii, "BootOrder") == 0)
            has_bootorder = true;
        else if (strcmp(ascii, "ConOut") == 0)
            has_conout = true;

        variable_destroy_noalloc(&vars[i]);
    }

    munit_assert(has_bootorder);
    munit_assert(has_conout);
}

static void test_big_request(void)
{
    char buffer[4096 * 8];
    char *big_request = BIG_REQUEST;

    base64_from_response(buffer, 4096 * 8, big_request);
}

static const char *expected_vars[] = { "Boot0002",
                                       "Boot0003",
                                       "Boot0004",
                                       "BootCurrent",
                                       "BootOptionSupport",
                                       "BootOrder",
                                       "ConIn",
                                       "ConInDev",
                                       "ConOut",
                                       "ConOutDev",
                                       "ErrOut",
                                       "ErrOutDev",
                                       "Key0000",
                                       "Lang",
                                       "LangCodes",
                                       "MTC",
                                       "MemoryTypeInformation",
                                       "OsIndicationsSupported",
                                       "PlatformLang",
                                       "PlatformLangCodes",
                                       "PlatformRecovery0000",
                                       "SecureBoot",
                                       "SetupMode",
                                       "Timeout" };

static void test_big_request2(void)
{
    variable_t vars[32];
    char buffer[4096 * 8];
    char *big_request = BIG_REQUEST2;
    uint8_t plaintext[BIG_MESSAGE_SIZE];
    char ascii[128] = { '\0' };
    const char *name;
    int ret;
    bool found;

    memset(vars, 0, sizeof(vars));

    ret = base64_from_response(buffer, 4096 * 8, big_request);
    ret = base64_to_bytes(plaintext, BIG_MESSAGE_SIZE, buffer, strlen(buffer));

    from_bytes_to_vars(vars, 32, plaintext, (size_t)ret);

    int i, j;

    for (i = 0; i < sizeof(expected_vars) / sizeof(expected_vars[0]); i++) {
        name = expected_vars[i];
        found = false;

        for (j = 0; j < 32; j++) {
            uc2_ascii(vars[j].name, ascii, 128);

            if (strcmp(ascii, name) == 0) {
                found = true;
                break;
            }
        }

        munit_assert(found == true);
    }

    for (i = 0; i < 32; i++) {
        variable_destroy_noalloc(&vars[i]);
    }
}

#define DO_TEST(test) do { pre_test(); test(); post_test(); } while( 0 )

void test_xapi(void)
{
    v1_len = strsize16((char16_t *)v1) + sizeof(UTF16);
    d1_len = strlen(D1);
    v2_len = strsize16((char16_t *)v2) + sizeof(UTF16);
    d2_len = strlen(D2);

    blocksz = v1_len + sizeof(v1_len) + d1_len + sizeof(d1_len) + v2_len +
              sizeof(v2_len) + d2_len + sizeof(d2_len);

    memset(vars, 0, sizeof(vars));

    variable_create_noalloc(&vars[0], v1, (uint8_t *)D1, d1_len, &default_guid,
                            DEFAULT_ATTR, NULL);
    variable_create_noalloc(&vars[1], v2, (uint8_t *)D2, d2_len, &default_guid,
                            DEFAULT_ATTR, NULL);

    //DO_TEST(test_xapi_set_efi_vars);
    DO_TEST(test_var_copy);
    DO_TEST(test_bytes);
    DO_TEST(test_xapi_base64);
    DO_TEST(test_xapi_base64_big);
    DO_TEST(test_xapi_base64_big_xml);
    DO_TEST(test_big_request);
    DO_TEST(test_big_request2);
}
