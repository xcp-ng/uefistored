#include <string.h>

#include "storage.h"
#include "common.h"
#include "data/bigbase64.h"
#include "test_common.h"
#include "test_xapi.h"
#include "log.h"
#include "xapi.h"
#include "variables_service.h"

#include "test_common.h"
#include "test_storage.h"


static UTF16 RTC[] = { 'R', 'T', 'C', 0 };
static uint8_t RTC_DATA[] = { 0xa, 0xb, 0xc, 0xd };
static UTF16 CHEER[] = { 'C', 'H', 'E', 'E', 'R', 0 };
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
    EFI_STATUS ret;

    variable_t tmp = { 0 };

    variable_create_noalloc(&tmp, var1.name, var1.data, var1.datasz, &var1.guid,
                            var1.attrs);

    ret = storage_set(var1.name, &var1.guid, var1.data, var1.datasz,
                      var1.attrs);
    test(ret == 0);

    ret = storage_get(var1.name, &var1.guid, &var1.attrs, var1.data, &var1.datasz);
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
    EFI_STATUS ret;

    variable_t tmp;

    tmp.name = malloc(MAX_VARIABLE_NAME_SIZE);
    tmp.data = malloc(MAX_VARIABLE_DATA_SIZE);
    tmp.datasz = MAX_VARIABLE_DATA_SIZE;
    memcpy(&tmp.guid, &var1.guid, sizeof(tmp.guid));
    tmp.namesz = var1.namesz;
    strncpy16(tmp.name, var1.name, MAX_VARIABLE_NAME_SIZE);

    ret = storage_set(var1.name, &var1.guid, var1.data, var1.datasz,
                      var1.attrs);
    test(ret == 0);

    ret = storage_get(tmp.name, &tmp.guid, &tmp.attrs, tmp.data, &tmp.datasz);

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

    tmp.datasz = MAX_VARIABLE_DATA_SIZE;
    ret = storage_get(tmp.name, &tmp.guid, &tmp.attrs, tmp.data, &tmp.datasz);
    test(ret == 0);

    test(variable_eq(&var2, &tmp));

    free(tmp.data);
    free(tmp.name);
}

static void test_next(void)
{
    EFI_STATUS status;

    UTF16 next[MAX_VARIABLE_NAME_SIZE];
    size_t next_sz = MAX_VARIABLE_NAME_SIZE;
    EFI_GUID next_guid = DEFAULT_GUID;

    memset(&next, 0, sizeof(next));

    storage_set(var1.name, &var1.guid, var1.data, var1.datasz, var1.attrs);
    storage_set(var2.name, &var1.guid, var2.data, var2.datasz, var2.attrs);

    next_sz = MAX_VARIABLE_NAME_SIZE;
    status = storage_next(&next_sz, next, &next_guid);
    test(status == 0);

    next_sz = MAX_VARIABLE_NAME_SIZE;
    status = storage_next(&next_sz, next, &next_guid);
    test(status == 0);

    next_sz = MAX_VARIABLE_NAME_SIZE;
    status = storage_next(&next_sz, next, &next_guid);
    test(status == EFI_NOT_FOUND);
}

#define DEFINE_VAR(_name, _data)         \
        {                                \
            .name = (UTF16*)_name,       \
            .namesz = sizeof(_name),     \
            .data = (uint8_t*)_data,     \
            .datasz = sizeof(_data),     \
            .guid = DEFAULT_GUID,        \
            .attrs = DEFAULT_ATTR        \
        }

static void test_next_after_remove(void)
{
    EFI_STATUS status;
    UTF16 next[MAX_VARIABLE_NAME_SIZE] = { 0 };
    size_t next_sz = MAX_VARIABLE_NAME_SIZE;
    EFI_GUID next_guid = DEFAULT_GUID;
    variable_t vars[] = {
        DEFINE_VAR(L"VAR1", L"DATA1"),
        DEFINE_VAR(L"VAR2", L"DATA2"),
        DEFINE_VAR(L"VAR3", L"DATA3"),
        DEFINE_VAR(L"VAR4", L"DATA4"),
        DEFINE_VAR(L"VAR5", L"DATA5"),
    };
    size_t i;

    for (i=0; i<sizeof(vars)/sizeof(vars[0]); i++) {
        status = storage_set(vars[i].name, &vars[i].guid,
                    vars[i].data, vars[i].datasz,
                    vars[i].attrs);
    }

    for (i=0; i<sizeof(vars)/sizeof(vars[0]); i++) {
        next_sz = MAX_VARIABLE_NAME_SIZE;
        status = storage_next(&next_sz, next, &next_guid);
        test(status == EFI_SUCCESS);
        test(strcmp16((UTF16*)next, (UTF16*)vars[i].name) == 0);
    }

    next_sz = MAX_VARIABLE_NAME_SIZE;
    status = storage_next(&next_sz, next, &next_guid);
    test(status == EFI_NOT_FOUND);

    /* Remove vars 2 and 3 */
    status = storage_set(vars[1].name, &vars[1].guid,
                vars[1].data, vars[1].datasz,
                0);
    test(status == 0);

    status = storage_set(vars[2].name, &vars[2].guid,
                vars[2].data, vars[2].datasz,
                0);
    test(status == 0);

    next_sz = MAX_VARIABLE_NAME_SIZE;
    memset(next, 0, sizeof(next));

    for (i=0; i<sizeof(vars)/sizeof(vars[0]); i++) {

        /* skip the two we removed */
        if (i == 1 || i == 2)
            continue;

        next_sz = MAX_VARIABLE_NAME_SIZE;
        status = storage_next(&next_sz, next, &next_guid);
        test(status == EFI_SUCCESS);
        test(strcmp16((UTF16*)next, (UTF16*)vars[i].name) == 0);
    }

    next_sz = MAX_VARIABLE_NAME_SIZE;
    status = storage_next(&next_sz, next, &next_guid);
    test(status == EFI_NOT_FOUND);
}

static void test_set_different_attrs(void)
{
    EFI_STATUS status;
    EFI_GUID guid = DEFAULT_GUID;
    variable_t vars[] = {
        DEFINE_VAR(L"TestVariable1", L"DATA1"),
    };
    variable_t *var = &vars[0];
    UTF16 name[MAX_VARIABLE_NAME_SIZE] = { 0 };
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    size_t datasz = MAX_VARIABLE_DATA_SIZE;
    uint32_t attrs[] = {
        EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        EFI_VARIABLE_NON_VOLATILE | \
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
    };
    uint32_t attr = 0;
    size_t i;

    set_efi_runtime(false);

    memcpy(name, var->name, var->namesz);

    for (i=0; i<sizeof(attrs)/sizeof(attrs[0]); i++) {
        status = storage_set(var->name, &var->guid, var->data, var->datasz, attrs[i]);

        if (i == 0)
            test(status == EFI_SUCCESS);
        else
            test(status == EFI_INVALID_PARAMETER);

        status = storage_get(name, &guid, &attr, data, &datasz);
        test(status == EFI_SUCCESS);
    }
}

static void test_set_different_attrs_delete_first(void)
{
    EFI_STATUS status, returned_status;
    variable_t vars[] = {
        DEFINE_VAR(L"TestVariable1", L"DATA1"),
    };
    variable_t *var = &vars[0];
    uint32_t attrs[] = {
        EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        EFI_VARIABLE_NON_VOLATILE | \
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
    };
    size_t i;
    UTF16 name[MAX_VARIABLE_NAME_SIZE] = { 0 };
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    size_t datasz = MAX_VARIABLE_DATA_SIZE;
    uint32_t attr;
    EFI_GUID guid = DEFAULT_GUID;

    set_efi_runtime(false);

    memcpy(name, var->name, var->namesz);

    for (i=0; i<sizeof(attrs)/sizeof(attrs[0]); i++) {
        status = storage_set(var->name, &var->guid, var->data, var->datasz, attrs[i]);
        test(status == EFI_SUCCESS);

        returned_status = storage_set(var->name, &var->guid, var->data, 0, attrs[i]);
        status = storage_set(var->name, &var->guid, var->data, 0, attrs[i]);

        printf("returned_status=%s, status=%s\n",
                efi_status_str(returned_status), efi_status_str(status));

        test(returned_status == EFI_SUCCESS && status == EFI_NOT_FOUND);

        status = storage_get(name, &guid, &attr, data, &datasz);
        test(status == EFI_NOT_FOUND);
    }
}

void test_storage(void)
{
    EFI_GUID default_guid = DEFAULT_GUID;

    variable_create_noalloc(&var1, RTC, RTC_DATA, sizeof(RTC_DATA),
                            &default_guid, DEFAULT_ATTR);
    variable_create_noalloc(&var2, CHEER, CHEER_DATA, sizeof(CHEER_DATA),
                            &default_guid, DEFAULT_ATTR);

    DO_TEST(test_set_and_get);
    DO_TEST(test_set_and_get2);
    DO_TEST(test_next);
    DO_TEST(test_next_after_remove);
    DO_TEST(test_set_different_attrs);
    DO_TEST(test_set_different_attrs_delete_first);

    variable_destroy_noalloc(&var1);
    variable_destroy_noalloc(&var2);
}
