#include <string.h>

#include "test_common.h"
#include "xapi_nvram.h"
#include "common.h"

static void pre_test(void)
{
}

static void post_test(void)
{
}

#include "test_xapi_nvram.h"

#define SET_NVRAM_EFI_VARS_TEMPLATE 							\
	"<?xml version='1.0'?>"								\
	"<methodCall>"									\
	"<methodName>VM.set_NVRAM_EFI_variables</methodName>"				\
		"<params>"								\
			"<param><value><string>DUMMYSESSION</string></value></param>"	\
			"<param><value><string>DUMMYVM</string></value></param>"	\
			"<param><value><string>%s</string></value></param>"		\
		"</params>"								\
	"</methodCall>"

#define v1 "HELLO"
#define d1 "WORLD!"
#define v2 "FOO"
#define d2 "bar"

static size_t v1_len;
static size_t d1_len;
static size_t v2_len;
static size_t d2_len;
static size_t blocksz;

serializable_var_t vars[2];


void test_xapi_nvram_serialize(void)
{
    size_t size;

    size = xapi_nvram_serialized_size((serializable_var_t*)vars, 2);

    test(size == blocksz);
}


void test_xapi_nvram(void)
{
    v1_len = strlen(v1); // 5
    d1_len = strlen(d1); // 6
    v2_len = strlen(v2); // 3
    d2_len = strlen(d2); // 3

    blocksz = v1_len + sizeof(v1_len) +
                 d1_len + sizeof(d1_len) +
                 v2_len + sizeof(v2_len) +
                 d2_len + sizeof(d2_len);

    vars[0].variable = (uint8_t*)v1;
    vars[0].variable_len = v1_len;
    vars[0].data = (uint8_t*)d1;
    vars[0].data_len = d1_len;

    vars[1].variable = (uint8_t*)v2;
    vars[1].variable_len = v2_len;
    vars[1].data = (uint8_t*)d2;
    vars[1].data_len = d2_len;

    DO_TEST(test_xapi_nvram_serialize);
}
