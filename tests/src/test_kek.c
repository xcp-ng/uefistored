#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "storage.h"
#include "uefi/auth.h"
#include "uefi/authlib.h"
#include "uefi/guids.h"
#include "uefi/types.h"
#include "uefi/pkcs7_verify.h"
#include "uefi/image_authentication.h"

#include "test_common.h"

#include "munit.h"

static struct auth_data auth_files[] = {
    DEFINE_AUTH_FILE("data/certs/PK.auth", L"PK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
};

#define BUF_SIZE 4096

#define KEK_ATTRS (EFI_VARIABLE_RUNTIME_ACCESS | \
                   EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                   EFI_VARIABLE_NON_VOLATILE | \
                   EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

extern EFI_GUID gEfiGlobalVariableGuid;

EFI_STATUS util_set_kek(void *data, size_t n)
{
    return auth_lib_process_variable(L"KEK", sizeof_wchar(L"KEK"),
                                     &gEfiGlobalVariableGuid,
                                     data, n, KEK_ATTRS);
}

static MunitResult test_valid_first_kek(const MunitParameter params[], void *testdata)
{

    uint8_t kek[BUF_SIZE];
    int ret;

    if ((ret = file_to_buf("data/certs/KEK.auth", kek, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/KEK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_kek(kek, ret), ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static void *kek_setup(const MunitParameter params[], void* user_data)
{
    auth_lib_load(auth_files, ARRAY_SIZE(auth_files));
    auth_lib_initialize(auth_files, ARRAY_SIZE(auth_files));
    return NULL;
}

static void kek_tear_down(void* fixture)
{
    auth_lib_deinit(auth_files, ARRAY_SIZE(auth_files));
    storage_destroy();
}

MunitTest kek_tests[] = {
    { (char*)"test_valid_first_kek", test_valid_first_kek,
        kek_setup, kek_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
