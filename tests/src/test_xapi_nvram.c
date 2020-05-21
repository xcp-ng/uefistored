#include <string.h>

#include "test_common.h"
#include "test_xapi_nvram.h"
#include "backends/filedb.h"
#include "xapi_nvram.h"
#include "common.h"


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

static void test_xapi_nvram_serialize_size(void)
{
    size_t size;

    size = xapi_nvram_serialized_size((serializable_var_t*)vars, 2);

    test(size == blocksz);
}

static void test_xapi_nvram_serialize(void)
{
    uint8_t *p;
    void *data;
    size_t size, tmp;

    size = xapi_nvram_serialized_size((serializable_var_t*)vars, 2);
    data = malloc(size);
    xapi_nvram_serialize((serializable_var_t*)vars, 2, data, size);

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

void test_xapi_nvram_set_efi_vars(void)
{
    serializable_var_t *var;
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

    xapi_nvram_set_efi_vars();
}

void test_xapi_nvram(void)
{
    v1_len = strlen16((char16_t*)v1) * 2;
    d1_len = strlen(D1);
    v2_len = strlen16((char16_t*)v2) * 2; 
    d2_len = strlen(D2);

    blocksz = v1_len + sizeof(v1_len) +
              d1_len + sizeof(d1_len) +
              v2_len + sizeof(v2_len) +
              d2_len + sizeof(d2_len);

    vars[0].variable = malloc(v1_len); 
    memcpy(vars[0].variable, v1, v1_len);
    vars[0].variable_len = v1_len;
    vars[0].data = (uint8_t*)D1;
    vars[0].data_len = d1_len;

    vars[1].variable = malloc(v2_len); 
    memcpy(vars[1].variable, v2, v2_len);
    vars[1].variable_len = v2_len;
    vars[1].data = (uint8_t*)D2;
    vars[1].data_len = d2_len;

    DO_TEST(test_xapi_nvram_serialize_size);
    DO_TEST(test_xapi_nvram_serialize);
    DO_TEST(test_xapi_nvram_set_efi_vars);
}
