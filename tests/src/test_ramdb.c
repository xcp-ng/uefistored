#include <string.h>

#include "common.h"
#include "data/bigbase64.h"
#include "test_common.h"
#include "test_xapi.h"
#include "backends/backend.h"
#include "xapi.h"
#include "backends/ramdb.h"

#include "test_common.h"
#include "test_ramdb.h"

static variable_t var1 = {
    .name =  {'R', 'T', 'C'},
    .namesz =  3,
    .data = { 0xa, 0xb, 0xc, 0xd },
    .datasz = 4,
    .attrs = 0x5,
};

static variable_t var2 = {
    .name = {'C', 'H', 'E', 'E', 'R'},
    .namesz =  5,
    .data = { 0xa, 0xb, 0xc, 0xd, 0xf, 0xf },
    .datasz = 6,
    .attrs = 0x4,
};

static void pre_test(void)
{
    ramdb_init();
}

static void post_test(void)
{
    ramdb_destroy();
}

static void test_set_and_get(void)
{
    int ret;

    variable_t tmp;

    memcpy(tmp.name, var1.name, var1.namesz);
    memcpy(&tmp.namesz, &var1.namesz, sizeof(var1.namesz));

    ret = ramdb_set(var1.name, var1.data, var1.datasz, var1.attrs);
    test( ret == 0 );

    ret = ramdb_get(var1.name, tmp.data, MAX_VARDATA_SZ, &tmp.datasz, &tmp.attrs);
    test( ret == 0 );

    test( var1.namesz == tmp.namesz );
    test( var1.datasz == tmp.datasz );
    test( memcmp(tmp.name, var1.name, var1.namesz) == 0 );
    test( memcmp(tmp.data, var1.data, var1.datasz) == 0 );
    test( var1.attrs == tmp.attrs );
}

static void test_set_and_get2(void)
{
    int ret;

    variable_t tmp;

    memcpy(tmp.name, var1.name, var1.namesz);
    memcpy(&tmp.namesz, &var1.namesz, sizeof(var1.namesz));

    ret = ramdb_set(var1.name, var1.data, var1.datasz, var1.attrs);
    test( ret == 0 );

    ret = ramdb_get(tmp.name, tmp.data, MAX_VARDATA_SZ, &tmp.datasz, &tmp.attrs);
    test( ret == 0 );

    test( var1.namesz == tmp.namesz );
    test( var1.datasz == tmp.datasz );
    test( memcmp(tmp.name, var1.name, var1.namesz) == 0 );
    test( memcmp(tmp.data, var1.data, var1.datasz) == 0 );
    test( var1.attrs == tmp.attrs );

    memcpy(tmp.name, var2.name, var2.namesz);
    memcpy(&tmp.namesz, &var2.namesz, sizeof(var2.namesz));

    ret = ramdb_set(var2.name, var2.data, var2.datasz, var2.attrs);
    test( ret == 0 );

    ret = ramdb_get(tmp.name, tmp.data, MAX_VARDATA_SZ, &tmp.datasz, &tmp.attrs);
    test( ret == 0 );

    test( var2.namesz == tmp.namesz );
    test( var2.datasz == tmp.datasz );
    test( memcmp(tmp.name, var2.name, var2.namesz) == 0 );
    test( memcmp(tmp.data, var2.data, var2.datasz) == 0 );
    test( var2.attrs == tmp.attrs );
}

static void test_next(void)
{
    int ret;

    variable_t cur, next, after, final;

    memset(&cur, 0, sizeof(cur));
    memset(&next, 0, sizeof(next));
    memset(&after, 0, sizeof(after));
    memset(&final, 0, sizeof(final));

    ramdb_set(var1.name, var1.data, var1.datasz, var1.attrs);
    ramdb_set(var2.name, var2.data, var2.datasz, var2.attrs);

    ret = ramdb_next(&cur, &next);
    test( ret == 1 );

    ret = ramdb_next(&next, &after);
    test( ret == 1 );

    ret = ramdb_next(&after, &final);
    DEBUG("ret=%d\n", ret);
    test( ret == 0 );
}

void test_ramdb(void)
{
    DO_TEST(test_set_and_get);
    DO_TEST(test_set_and_get2);
    DO_TEST(test_next);
}
