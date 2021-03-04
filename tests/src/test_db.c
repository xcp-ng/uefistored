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
#include "test_suites.h"

#include "munit.h"

#define BUF_SIZE 4096
extern EFI_GUID gEfiGlobalVariableGuid;

EFI_STATUS util_set_kek(void *data, size_t n);

static inline EFI_STATUS util_set_db(void *data, size_t n)
{
    return auth_lib_process_variable(L"db", sizeof_wchar(L"db"),
                                     &gEfiImageSecurityDatabaseGuid,
                                     data, n, AT_ATTRS);
}

static MunitResult test_db_signed_by_pk(const MunitParameter params[], void *testdata)
{

    uint8_t db[BUF_SIZE];
    int len;

    if ((len = file_to_buf("data/certs/DB-signed-by-PK.auth", db, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/DB-signed-by-PK.auth: %d\n", len);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_db(db, len), ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_db_signed_by_kek(const MunitParameter params[], void *testdata)
{

    uint8_t db[BUF_SIZE];
    int len;

    if ((len = file_to_buf("data/certs/DB-signed-by-KEK.auth", db, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/DB-signed-by-KEK.auth: %d\n", len);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_db(db, len), ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static struct auth_data auth_files[] = {
    DEFINE_AUTH_FILE("data/certs/PK.auth", L"PK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
};

static void *db_setup(const MunitParameter params[], void* user_data)
{
    EFI_STATUS status;
    uint8_t kek[BUF_SIZE];
    int ret;

    auth_lib_load(auth_files, ARRAY_SIZE(auth_files));
    auth_lib_initialize(auth_files, ARRAY_SIZE(auth_files));

    if ((ret = file_to_buf("data/certs/KEK.auth", kek, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/KEK.auth: %d\n", ret);
        exit(1);
    }

    if ((status = util_set_kek(kek, ret)) != EFI_SUCCESS) {
        fprintf(stderr, "failed to set kek: 0x%02lx", status);
        exit(1);
    }

    return NULL;
}

static void db_tear_down(void* fixture)
{
    storage_destroy();
}

MunitTest db_tests[] = {
    { (char*)"test_db_signed_by_pk", test_db_signed_by_pk,
        db_setup, db_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_db_signed_by_kek", test_db_signed_by_kek,
        db_setup, db_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
