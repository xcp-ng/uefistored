#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "backends/ramdb.h"
#include "data/bigbase64.h"
#include "data/bigrequest.h"
#include "common.h"
#include "log.h"
#include "test_common.h"
#include "test_xapi.h"
#include "xapi.h"
#include "mock/XenVariable.h"
#include "xen_variable_server.h"

#define TEST_PT_SIZE 512

static char *BIG_BASE64 =  BIG_BASE64_STR;
static char *BIG_BASE64_XML =  BIG_BASE64_XML_STR;

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static UTF16 v1[] = { 'B', 'C', '\0' };
static UTF16 v2[] = { 'Y', 'Z', '\0' };
static const UTF16 FOO[] = { 'F', 'O', 'O', '\0' };
static const UTF16 BAR[] = { 'B', 'A', 'R', '\0' };
static const UTF16 CHEER[] = { 'C', 'H', 'E', 'E', 'R', '\0' };
static const UTF16 ABCD[] = { 'A', 'B', 'C', 'D', '\0' };

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
    ramdb_init();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

static void post_test(void)
{
    ramdb_deinit();
    ramdb_destroy();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

void test_xapi_set_efi_vars(void)
{
    char readbuf[4096] = {0};
    int fd;
    variable_t *var;
    EFI_GUID guid;
    uint32_t attr = DEFAULT_ATTRS;

    var = &vars[0];
    mock_xen_variable_server_set_buffer(comm_buf);
    XenSetVariable(var->name, &guid, attr, var->datasz, (void*)var->data);
    xen_variable_server_handle_request(comm_buf);

    var = &vars[1];
    mock_xen_variable_server_set_buffer(comm_buf);
    XenSetVariable(var->name, &guid, attr, var->datasz, (void*)var->data);
    xen_variable_server_handle_request(comm_buf);

    xapi_set_efi_vars();

    fd = open("./mock_socket", O_RDWR | O_EXCL, S_IRWXU);
    
    test(fd > 0);
    test(read(fd, readbuf, 4096) >= 0);
    test(strstr(readbuf, "BAAAAAAAAABCAEMABgAAAAAAAABXT1JMRCEEAAAAAAAAAFkAWgADAAAAAAAAAGJh") != NULL);

    remove("./mock_socket");
}

static void test_blob(void)
{
    uint8_t blob[4096] = {0};
    uint8_t *p = (uint8_t*)blob;
    variable_t orig = {0};
    variable_t var = {0};

    /* Setup */
    variable_create_noalloc(&orig, FOO, (uint8_t*)BAR, strsize16(BAR), &DEFAULT_GUID, DEFAULT_ATTR);

    serialize_variable_list(&p, TEST_PT_SIZE, &orig, 1);
    from_blob_to_vars(&var, 1, blob, TEST_PT_SIZE);

    test(variable_eq(&orig, &var));
    variable_destroy_noalloc(&orig);
    variable_destroy_noalloc(&var);
}

static void test_var_copy(void)
{
    uint8_t buf[4096] = {0};
    uint8_t *p;
    variable_t orig = {0};
    variable_t *var;

    /* Setup */
    variable_create_noalloc(&orig, FOO, (uint8_t*)BAR, strsize16(BAR), &DEFAULT_GUID, DEFAULT_ATTR);


    /* Do the work */
    p = buf;
    serialize_var(&p, &orig);
    p = buf;
    var = variable_create_unserialize(&p);

    variable_printf(var);
    variable_printf(&orig);

    printf("var->namesz=%lu\n", var->namesz);
    printf("orig.namesz=%lu\n", orig.namesz);

    /* Do the test */
    test(variable_eq(var, &orig));

	variable_destroy(var);
    variable_destroy_noalloc(&orig);
}

#define EXPECTED_B64_ENC "VkFSUwEAAAABAAAAAAAAAGAAAAAAAAAABgAAAAAAA"     \
                         "ABGAE8ATwAGAAAAAAAAAAAAAAAAAN3Mu6"            \
                         "oAAAAAAAAAAAAAAADz8gAAAAAAAAAAAAA"            \
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"             \
                         "AAAAAAAAAAAAAAAAAAAAA"

/**
 * Passes if a variable list of size 1 serializes and encodes into
 * the correct base64 string.
 */
void test_base64_encode(void)
{
    char *base64;
    uint8_t buf[4096] = {0};
    uint8_t *p = (uint8_t*)buf;
    variable_t orig = {0};
    const char *expected = EXPECTED_B64_ENC;

    /* Setup */
    orig.namesz = strsize16(FOO);
    orig.name = malloc(orig.namesz + sizeof(UTF16));
    strncpy16(orig.name, FOO, orig.namesz + sizeof(UTF16));

    orig.datasz = strsize16(BAR);
    orig.data = calloc(1, orig.datasz);
    strncpy16((UTF16*)orig.data, BAR, orig.datasz);

    orig.guid.Data1 = 0xaabbccdd;
    orig.attrs = 0xf2f3;

    /* Do the work */
    serialize_variable_list(&p, 4096, &orig, 1);
    base64 = blob_to_base64(buf, list_size(&orig, 1));

    /* Do the test */
    test(strcmp(base64, expected) == 0);
    free(base64);
    free(orig.name);
    free(orig.data);
}

/**
 * Passes if serializing a list of size 1 and then deserializig it results in
 * the same list of size 1.
 */
void test_base64(void)
{
    int sz;
    char *base64;
    uint8_t buf[4096] = {0};
    uint8_t *p = (uint8_t*)buf;
    uint8_t blob[4096] = {0};
    variable_t *orig;
    variable_t var = {0};

    /* Setup */
    orig = variable_create(FOO, (uint8_t*)BAR, strsize16(BAR), &DEFAULT_GUID, DEFAULT_ATTRS);

    /* Convert variable into blob, and then blob into base64 */
    serialize_variable_list(&p, 4096, orig, 1);
    base64 = blob_to_base64(buf, list_size(orig, 1));

    /* Convert base64 to blob, then blob back to variable */
    sz = base64_to_blob(blob, 4096, base64, strlen(base64)); 
    from_blob_to_vars(&var, 1, blob, sz); 

    /* Assert the original variable and the decoded variable are equal */
    test(variable_eq(&var, orig));

    /* Cleanup */
    free(base64);
    variable_destroy(orig);
    variable_destroy_noalloc(&var);
}

#define VARCNT 2
#define BUFSZ (4096*2)
#define EXPECTED_BASE64_MULT "VkFSUwEAAAACAAAA"\
                             "AAAAAMYAAAAAAAAA"\
                             "BgAAAAAAAABGAE8A"\
                             "TwAGAAAAAAAAAEIA"\
                             "QQBSAO3+3sAAAAAA"\
                             "AAAAAAAAAADvvq3e"\
                             "AAAAAAAAAAAAAAAA"\
                             "AAAAAAAAAAAAAAAA"\
                             "AAAAAAAAAAAAAAAA"\
                             "AAAAAAAAAAAAAAAA"\
                             "CgAAAAAAAABDAEgA"\
                             "RQBFAFIACAAAAAAA"\
                             "AABBAEIAQwBEAO3+"\
                             "3sAAAAAAAAAAAAAA"\
                             "AADvvq3eAAAAAAAA"\
                             "AAAAAAAAAAAAAAAA"\
                             "AAAAAAAAAAAAAAAA"\
                             "AAAAAAAAAAAAAAAA"\
                             "AAAAAAAA"


void test_base64_multiple(void)
{
    int ret;
    char *base64;
    const char *expected = EXPECTED_BASE64_MULT;
    uint8_t buf[BUFSZ] = {0};
    uint8_t *p = (uint8_t*)buf;
    uint8_t blob[BUFSZ] = {0};
    variable_t orig[VARCNT] = {0};
    variable_t var[VARCNT] = {0};

    /* Setup */
    variable_create_noalloc(&orig[0], FOO, (uint8_t*)BAR, strsize16(BAR), &DEFAULT_GUID, DEFAULT_ATTRS);
    variable_create_noalloc(&orig[1], CHEER, (uint8_t*)ABCD, strsize16(ABCD), &DEFAULT_GUID, DEFAULT_ATTRS);

    /* Do the work */
    serialize_variable_list(&p, BUFSZ, orig, sizeof(orig) / sizeof(orig[0]));
    base64 = blob_to_base64(buf, list_size(orig, VARCNT));

    /* Test the base64 encoding */
    test(strcmp(base64, expected) == 0);
    ret = base64_to_blob(blob, BUFSZ, base64, strlen(base64)); 
    from_blob_to_vars(var, VARCNT, blob, ret); 

    /* Do the test */
    test(variable_eq(&var[0], &orig[0]));
    test(variable_eq(&var[1], &orig[1]));

    variable_destroy_noalloc(&orig[0]);
    variable_destroy_noalloc(&orig[1]);
    variable_destroy_noalloc(&var[0]);
    variable_destroy_noalloc(&var[1]);

    free(base64);
}

void test_base64_big(void)
{
    bool has_bootorder = false, has_conout = false;
    int ret;
    int i;
    uint8_t pt[4096*4];
    variable_t vars[256] = {0};

    ret = base64_to_blob(pt, 4096*4, BIG_BASE64, strlen(BIG_BASE64));
    test(ret > 0);

    ret = from_blob_to_vars(vars, 256, pt, ret); 

    for ( i=0; i<ret; i++ )
    {
        char ascii[512];

        uc2_ascii(vars[i].name, ascii, 512);

        if ( strcmp(ascii, "BootOrder") == 0 )
            has_bootorder = true;
        else if ( strcmp(ascii, "ConOut") == 0 )
            has_conout = true;

        variable_destroy_noalloc(&vars[i]);
    }

    test(has_bootorder);
    test(has_conout);
}

void test_base64_big_xml(void)
{
    bool has_bootorder = false, has_conout = false;
    int ret;
    int i;
    char base64[4096*4];
    uint8_t pt[4096*4];
    variable_t vars[256] = {0};

    ret = base64_from_response_body(base64, 4096*4, BIG_BASE64_XML);
    test( ret == 0 );

    ret = base64_to_blob(pt, 4096*4, base64, strlen(base64));
    test(ret > 0);

    ret = from_blob_to_vars(vars, 256, pt, ret); 

    for ( i=0; i<ret; i++ )
    {
        char ascii[512];
        uc2_ascii(vars[i].name, ascii, 512);

        if ( strcmp(ascii, "BootOrder") == 0 )
            has_bootorder = true;
        else if ( strcmp(ascii, "ConOut") == 0 )
            has_conout = true;

        variable_destroy_noalloc(&vars[i]);
    }

    test(has_bootorder);
    test(has_conout);
}

static void test_big_request(void)
{
    char buffer[4096*8];
    char *big_request = BIG_REQUEST;

    base64_from_response(buffer, 4096*8, big_request);
}

void test_xapi(void)
{
    v1_len = strsize16((char16_t*)v1) + sizeof(UTF16);
    d1_len = strlen(D1);
    v2_len = strsize16((char16_t*)v2) + sizeof(UTF16); 
    d2_len = strlen(D2);

    blocksz = v1_len + sizeof(v1_len) +
              d1_len + sizeof(d1_len) +
              v2_len + sizeof(v2_len) +
              d2_len + sizeof(d2_len);

    memset(vars, 0, sizeof(vars));

    variable_create_noalloc(&vars[0], v1, (uint8_t*)D1, d1_len, &DEFAULT_GUID, DEFAULT_ATTRS);
    variable_create_noalloc(&vars[1], v2, (uint8_t*)D2, d2_len, &DEFAULT_GUID, DEFAULT_ATTRS);

    //DO_TEST(test_xapi_set_efi_vars);
    DO_TEST(test_var_copy);
    DO_TEST(test_blob);
    DO_TEST(test_base64);
    DO_TEST(test_base64_multiple);
    DO_TEST(test_base64_encode);
    DO_TEST(test_base64_big);
    DO_TEST(test_base64_big_xml);
    DO_TEST(test_big_request);
}
