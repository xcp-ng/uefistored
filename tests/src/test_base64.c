#include "munit/munit.h"

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "serializer.h"
#include "variable.h"
#include "test_common.h"

#define BUFFER_MAX (4096*4)
#define VAR_MAX 512

char *bytes_to_base64(uint8_t *buffer, size_t length);
int base64_to_bytes(uint8_t *plaintext, size_t n, char *encoded,
                    size_t encoded_size);

MunitResult test_base64(const MunitParameter *params, void* data)
{
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

    ret = from_bytes_to_vars(vars, VAR_MAX, buffer, ret);
    munit_assert(ret >= 0);

    ptr = serialized;
    ret = serialize_variable_list(&ptr, BUFFER_MAX, vars, ret);

    munit_assert(ret >= 0);
    munit_assert_int(memcmp(serialized, buffer, BUFFER_MAX), ==, 0);

    return MUNIT_OK;
}

MunitTest base64_tests[] = {
    { (char*)"test_base64", test_base64,
        NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
