#include <stdint.h>

#include "test_common.h"
#include "serializer.h"
#include "xapi.h"
#include "data/bigbase64.h"

static const uint8_t plaintext[] = MANY_VARS_ARR;
static variable_t vars[128] = { { 0 } };

void test_deserialization(void)
{
    int ret, i;
    char name[512] = { 0 };

    printf("\n%s\n", __func__);

    ret = from_bytes_to_vars(vars, 128, plaintext, sizeof(plaintext));
    printf("ret=%d\n", ret);

    for (i = 0; i < ret; i++) {
        uc2_ascii(vars[i].name, name, 512);
        printf("name: %s\n", name);
    }
}
