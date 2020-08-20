#include <string.h>

#include "storage.h"
#include "common.h"
#include "data/bigbase64.h"
#include "test_common.h"
#include "test_xapi.h"
#include "log.h"
#include "xapi.h"

#include "test_common.h"
#include "test_storage.h"

static UTF16 RTC[] = { 'R', 'T', 'C' };
static uint8_t RTC_DATA[] = { 0xa, 0xb, 0xc, 0xd };
static UTF16 CHEER[] = { 'C', 'H', 'E', 'E', 'R' };
static uint8_t CHEER_DATA[] = { 0xa, 0xb, 0xc, 0xd, 0xf, 0xf };

static variable_t var1 = { .attrs = DEFAULT_ATTR, .guid = DEFAULT_GUID };

static variable_t var2 = { .attrs = DEFAULT_ATTR, .guid = DEFAULT_GUID };

static void pre_test(void)
{
    storage_init();
}

static void post_test(void)
{
    storage_destroy();
}

static void test_set_and_get(void)
{
    int ret;

    variable_t tmp = { 0 };

    variable_create_noalloc(&tmp, var1.name, var1.data, var1.datasz, &var1.guid,
                            var1.attrs);

    ret = storage_set(var1.name, &var1.guid, var1.data, var1.datasz,
                      var1.attrs);
    test(ret == 0);

    ret = storage_get(var1.name, &tmp.guid, tmp.data, MAX_VARIABLE_DATA_SIZE,
                      &tmp.datasz, &tmp.attrs);
    test(ret == 0);

    test(var1.namesz == tmp.namesz);
    test(var1.datasz == tmp.datasz);
    test(memcmp(tmp.name, var1.name, var1.namesz) == 0);
    test(memcmp(tmp.data, var1.data, var1.datasz) == 0);
    test(var1.attrs == tmp.attrs);

    variable_destroy_noalloc(&tmp);
}

static void test_set_and_get2(void)
{
    int ret;

    variable_t tmp;

    tmp.name = malloc(MAX_VARIABLE_NAME_SIZE);
    tmp.data = malloc(MAX_VARIABLE_DATA_SIZE);
    memcpy(&tmp.guid, &var1.guid, sizeof(tmp.guid));
    tmp.namesz = var1.namesz;
    strncpy16(tmp.name, var1.name, MAX_VARIABLE_NAME_SIZE);

    ret = storage_set(var1.name, &var1.guid, var1.data, var1.datasz,
                      var1.attrs);
    test(ret == 0);

    ret = storage_get(tmp.name, &tmp.guid, tmp.data, MAX_VARIABLE_DATA_SIZE,
                      &tmp.datasz, &tmp.attrs);

    test(ret == 0);

    test(var1.namesz == tmp.namesz);
    test(var1.datasz == tmp.datasz);
    test(strcmp16(tmp.name, var1.name) == 0);
    test(memcmp(tmp.data, var1.data, var1.datasz) == 0);
    test(var1.attrs == tmp.attrs);

    strncpy16(tmp.name, var2.name, MAX_VARIABLE_NAME_SIZE);
    tmp.namesz = var2.namesz;

    ret = storage_set(var2.name, &var1.guid, var2.data, var2.datasz,
                      var2.attrs);
    test(ret == 0);

    ret = storage_get(tmp.name, &tmp.guid, tmp.data, MAX_VARIABLE_DATA_SIZE,
                      &tmp.datasz, &tmp.attrs);
    test(ret == 0);

    test(variable_eq(&var2, &tmp));

    free(tmp.data);
    free(tmp.name);
}

static void test_next(void)
{
    int ret;

    variable_t cur, next, after, final;

    memset(&cur, 0, sizeof(cur));
    memset(&next, 0, sizeof(next));
    memset(&after, 0, sizeof(after));
    memset(&final, 0, sizeof(final));

    storage_set(var1.name, &var1.guid, var1.data, var1.datasz, var1.attrs);
    storage_set(var2.name, &var1.guid, var2.data, var2.datasz, var2.attrs);

    ret = storage_next(&next);
    test(ret == 1);
    variable_destroy_noalloc(&next);

    ret = storage_next(&next);
    test(ret == 1);
    variable_destroy_noalloc(&next);

    ret = storage_next(&next);
    test(ret == 0);
    variable_destroy_noalloc(&next);
}

void test_storage(void)
{
    variable_create_noalloc(&var1, RTC, RTC_DATA, sizeof(RTC_DATA),
                            &DEFAULT_GUID, DEFAULT_ATTR);
    variable_create_noalloc(&var2, CHEER, CHEER_DATA, sizeof(CHEER_DATA),
                            &DEFAULT_GUID, DEFAULT_ATTR);

    DO_TEST(test_set_and_get);
    DO_TEST(test_set_and_get2);
    DO_TEST(test_next);

    variable_destroy_noalloc(&var1);
    variable_destroy_noalloc(&var2);
}
