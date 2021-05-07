#include <stdint.h>

#include "munit/munit.h"
#include "uefi/authlib.h"
#include "uefi/guids.h"
#include "uefi/types.h"
#include "storage.h"
#include "common.h"
#include "test_common.h"

static EFI_GUID guid = {0x15EDF297, 0xE832, 0x4d30, {0x82, 0x00, 0xA5, 0x25, 0xA9, 0x31, 0xE3, 0x3E}};

#define NAME L"TestVar"

static MunitResult test_append(const MunitParameter params[],
                               void *testdata)
{
    uint8_t buf[64] = {0};
    size_t len = 64;
    uint32_t attr, newattr;
    EFI_STATUS status;
    char *expected = "foobar";

    attr = EFI_VARIABLE_NON_VOLATILE | 
           EFI_VARIABLE_RUNTIME_ACCESS | 
           EFI_VARIABLE_BOOTSERVICE_ACCESS;

    status = testutil_set_variable(
                 NAME, 
                 sizeof_wchar(NAME), 
                 &guid, 
                 attr, 
                 sizeof("foo") - 1, 
                 (void*)"foo"
                 );

    munit_assert(status == EFI_SUCCESS);

    status = testutil_set_variable(
                 NAME, 
                 sizeof_wchar(NAME), 
                 &guid, 
                 attr | EFI_VARIABLE_APPEND_WRITE, 
                 sizeof("bar") - 1, 
                 (void*)"bar"
                 );

    munit_assert(status == EFI_SUCCESS);

    status = testutil_get_variable(
                 NAME, 
                 sizeof_wchar(NAME), 
                 &guid, 
                 &newattr, 
                 &len,
                 buf);

    munit_assert(status == EFI_SUCCESS);
    munit_assert_size(len, ==, 6);
    munit_assert(memcmp(buf, expected, len) == 0);

    return MUNIT_OK;
}

static void *setup(const MunitParameter params[], void *data)
{
    storage_destroy();
    return NULL;
}

static void tear_down(void* fixture)
{
    storage_destroy();
}

MunitTest append_tests[] = {
    { (char*)"test_append", test_append,
        setup, tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
