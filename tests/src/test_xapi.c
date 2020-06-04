#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "common.h"
#include "data/bigbase64.h"
#include "test_common.h"
#include "test_xapi.h"
#include "backends/filedb.h"
#include "xapi.h"

#define TEST_PT_SIZE 512

static char *BIG_BASE64 =  BIG_BASE64_STR;
static char *BIG_BASE64_XML =  BIG_BASE64_XML_STR;

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

char socket_path[108] = "/xapi-depriv-socket";

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

static char v1[] = { 'B', 0, 'C', 0, 0, 0, 0 };
static char v2[] = { 'Y', 0, 'Z', 0, 0, 0, 0 };

#define D1 "WORLD!"
#define D2 "bar"

static size_t v1_len;
static size_t d1_len;
static size_t v2_len;
static size_t d2_len;
static size_t blocksz;

serializable_var_t vars[2];

static void test_xapi_serialize_size(void)
{
    size_t size;

    size = xapi_serialized_size((serializable_var_t*)vars, 2);

    test(size == blocksz);
}

static void test_xapi_serialize(void)
{
    uint8_t *p;
    void *data;
    size_t size, tmp;

    size = xapi_serialized_size((serializable_var_t*)vars, 2);
    data = malloc(size);
    xapi_serialize((serializable_var_t*)vars, 2, data, size);

    p = data;

    /* Test Variable 1 was serialized correctly */
    memcpy(&tmp, p, sizeof(tmp));
    test(tmp == v1_len);
    p += sizeof(tmp);

    test(memcmp(p, v1, tmp) == 0);
    p += tmp;

    memcpy(&tmp, p, sizeof(tmp));
    test(tmp == d1_len);
    p += sizeof(tmp);

    test(memcmp(p, D1, tmp) == 0);
    p += tmp;

    /* Test Variable 2 was serialized correctly */
    memcpy(&tmp, p, sizeof(tmp));
    test(tmp == v2_len);
    p += sizeof(tmp);

    test(memcmp(p, v2, tmp) == 0);
    p += tmp;

    memcpy(&tmp, p, sizeof(tmp));
    test(tmp == d2_len);
    p += sizeof(tmp);

    test(memcmp(p, D2, tmp) == 0);
    p += tmp;

    free(data);
}

void test_xapi_set_efi_vars(void)
{
    char readbuf[4096] = {0};
    int fd;
    serializable_var_t *var;
    struct sockaddr_un saddr;
    uint8_t guid[16] = {0};
    uint32_t attr = DEFAULT_ATTR;

    var = &vars[0];
    mock_xenvariable_set_buffer(comm_buf);
    XenSetVariable(var->variable, &guid, attr, var->data_len, (void*)var->data);
    xenvariable_handle_request(comm_buf);

    var = &vars[1];
    mock_xenvariable_set_buffer(comm_buf);
    XenSetVariable(var->variable, &guid, attr, var->data_len, (void*)var->data);
    xenvariable_handle_request(comm_buf);

    xapi_set_efi_vars();

    fd = open("./random_socket_mock", O_RDWR | O_EXCL, S_IRWXU);
    
    test(fd > 0);
    test(read(fd, readbuf, 4096) >= 0);
    test(strstr(readbuf, "BAAAAAAAAABCAEMABgAAAAAAAABXT1JMRCEEAAAAAAAAAFkAWgADAAAAAAAAAGJh") != NULL);

    remove("./random_socket_mock");
}

static void test_blob(void)
{
    uint8_t blob[4096] = {0};
    variable_t orig = {0};
    variable_t var = {0};

    /* Setup */
    strcpy((char*)orig.name, "FOO");
    orig.namesz = strlen("FOO");
    strcpy((char*)orig.data, "BAR");
    orig.datasz = strlen("BAR");

    from_vars_to_blob(blob, TEST_PT_SIZE, &orig, 1);
    from_blob_to_vars(&var, 1, blob, TEST_PT_SIZE);

    test(memcmp(&var, &orig, sizeof(var)) == 0);
}

static void test_var_copy(void)
{
    uint8_t buf[4096] = {0};
    uint8_t *p = buf;
    variable_t orig = {0};
    variable_t var = {0};

    /* Setup */
    strcpy((char*)orig.name, "FOO");
    orig.namesz = strlen("FOO");
    strcpy((char*)orig.data, "BAR");
    orig.datasz = strlen("BAR");


    /* Do the work */
    serialize_var(&p, 4096, &orig);
    p = buf;
    unserialize_var(&var, &p);

    /* Do the test */
    test(memcmp(&var, &orig, sizeof(var)) == 0);
}

void test_base64_encode(void)
{
    char *base64;
    uint8_t buf[4096] = {0};
    variable_t orig = {0};
    const char *expected = "AwAAAAAAAABGT08DAAAAAAAAAEJBUg==";

    /* Setup */
    strcpy((char*)orig.name, "FOO");
    orig.namesz = strlen("FOO");
    strcpy((char*)orig.data, "BAR");
    orig.datasz = strlen("BAR");


    /* Do the work */
    from_vars_to_blob(buf, 4096, &orig, 1);
    base64 = blob_to_base64(buf, blob_size(&orig, 1));


    DEBUG("exp: %s\n", expected);
    /* Do the test */
    test(strcmp(base64, expected) == 0);
    free(base64);
}

void test_base64(void)
{
    int sz;
    char *base64;
    uint8_t buf[4096] = {0};
    uint8_t blob[4096] = {0};
    variable_t orig = {0};
    variable_t var = {0};

    /* Setup */
    strcpy((char*)orig.name, "FOO");
    orig.namesz = strlen("FOO");
    strcpy((char*)orig.data, "BAR");
    orig.datasz = strlen("BAR");


    /* Do the work */
    from_vars_to_blob(buf, 4096, &orig, 1);
    base64 = blob_to_base64(buf, blob_size(&orig, 1));

    sz = base64_to_blob(blob, 4096, base64, strlen(base64)); 
    from_blob_to_vars(&var, 1, blob, sz); 

    /* Do the test */
    test(memcmp(&var, &orig, sizeof(var)) == 0);
    free(base64);
}

#define VARCNT 2
#define BUFSZ (4096*2)

void test_base64_multiple(void)
{
    int ret;
    char *base64;
    const char *expected = "AwAAAAAAAABGT08DAAAAAAAAAEJBUgUAAAAAAAAAQ0hFRVIEAAAAAAAAAEFCQ0Q=";
    uint8_t buf[BUFSZ] = {0};
    uint8_t blob[BUFSZ] = {0};
    variable_t orig[VARCNT] = {0};
    variable_t var[VARCNT] = {0};

    /* Setup */
    strcpy((char*)orig[0].name, "FOO");
    orig[0].namesz = strlen("FOO");
    strcpy((char*)orig[0].data, "BAR");
    orig[0].datasz = strlen("BAR");

    strcpy((char*)orig[1].name, "CHEER");
    orig[1].namesz = strlen("CHEER");
    strcpy((char*)orig[1].data, "ABCD");
    orig[1].datasz = strlen("ABCD");


    /* Do the work */
    from_vars_to_blob(buf, BUFSZ, orig, VARCNT);

    base64 = blob_to_base64(buf, blob_size(orig, VARCNT));

    test(strcmp(base64, expected) == 0);

    ret = base64_to_blob(blob, BUFSZ, base64, strlen(base64)); 

    from_blob_to_vars(var, VARCNT, blob, ret); 

    /* Do the test */
    test(memcmp(&var[0], &orig[0], sizeof(var[0])) == 0);
    test(memcmp(&var[1], &orig[1], sizeof(var[1])) == 0);

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
        
    }

    test(has_bootorder);
    test(has_conout);

#if 0
    int i;

    DPRINTF("0x");
    for ( i=0; i<128; i++ )
    {
        DPRINTF("%02x", pt[i]);
    }
    DPRINTF("\n");
#endif
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
    }

    test(has_bootorder);
    test(has_conout);
}

void test_xapi(void)
{
    v1_len = strsize16((char16_t*)v1) + 2;
    d1_len = strlen(D1);
    v2_len = strsize16((char16_t*)v2) + 2; 
    d2_len = strlen(D2);

    blocksz = v1_len + sizeof(v1_len) +
              d1_len + sizeof(d1_len) +
              v2_len + sizeof(v2_len) +
              d2_len + sizeof(d2_len);

    vars[0].variable = malloc(v1_len); 
    memset(vars[0].variable, 0, v1_len);
    memcpy(vars[0].variable, v1, v1_len);
    vars[0].variable_len = v1_len;
    vars[0].data = (uint8_t*)D1;
    vars[0].data_len = d1_len;

    vars[1].variable = malloc(v2_len); 
    memset(vars[1].variable, 0, v2_len);
    memcpy(vars[1].variable, v2, v2_len);
    vars[1].variable_len = v2_len;
    vars[1].data = (uint8_t*)D2;
    vars[1].data_len = d2_len;

    DO_TEST(test_xapi_serialize_size);
    DO_TEST(test_xapi_serialize);
    //DO_TEST(test_xapi_set_efi_vars);
    DO_TEST(test_var_copy);
    DO_TEST(test_blob);
    DO_TEST(test_base64);
    DO_TEST(test_base64_multiple);
    DO_TEST(test_base64_encode);
    DO_TEST(test_base64_big);
    DO_TEST(test_base64_big_xml);

    free(vars[0].variable); 
    free(vars[1].variable); 
}
