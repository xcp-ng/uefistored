#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
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

static inline EFI_STATUS util_set_db(void *data, size_t n, bool append)
{
    uint32_t attrs = AT_ATTRS;

    if (append)
        attrs |= EFI_VARIABLE_APPEND_WRITE;

    return auth_lib_process_variable(L"db", sizeof_wchar(L"db"),
                                     &gEfiImageSecurityDatabaseGuid,
                                     data, n, attrs);
}

static inline EFI_STATUS util_get_db(void *data, size_t *n)
{
    EFI_GUID guid = gEfiImageSecurityDatabaseGuid;
    uint32_t attrs;

    return testutil_get_variable(
                 L"db",
                 sizeof_wchar(L"db"),
                 &guid,
                 &attrs,
                 n,
                 data);
}


static MunitResult test_db_signed_by_pk(const MunitParameter params[], void *testdata)
{

    uint8_t db[BUF_SIZE];
    int len;

    if ((len = file_to_buf("data/certs/db-signed-by-PK.auth", db, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/db-signed-by-PK.auth: %d\n", len);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_db(db, len, false), ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_db_signed_by_kek(const MunitParameter params[], void *testdata)
{

    uint8_t db[BUF_SIZE];
    int len;

    if ((len = file_to_buf("data/certs/db-signed-by-KEK.auth", db, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/db-signed-by-KEK.auth: %d\n", len);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_db(db, len, false), ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_db_append(const MunitParameter params[], void *testdata)
{
    EFI_STATUS status;
    uint8_t db[BUF_SIZE];
    int len;
    uint8_t old[BUF_SIZE];
    size_t old_len = BUF_SIZE;
    uint8_t new[BUF_SIZE];
    size_t new_len = BUF_SIZE;
    bool found;
    int i;

    if ((len = file_to_buf("data/certs/db.auth", db, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/db.auth: %d\n", len);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_db(db, len, false), ==, EFI_SUCCESS);
    munit_assert_uint64(util_get_db(old, &old_len), ==, EFI_SUCCESS);

    if ((len = file_to_buf("data/certs/db2.auth", db, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/db2.auth: %d\n", len);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_db(db, len, true), ==, EFI_SUCCESS);

    status = util_get_db(new, &new_len);
    munit_assert_uint64(status, ==, EFI_SUCCESS);
    munit_assert_size(new_len, >, old_len);

    found = false;
    for (i=0; i<(new_len - old_len); i++) {
        if ( memcmp(old, &new[i], old_len) == 0 )
            found = true;
    }
    munit_assert(found);

    return MUNIT_OK;
}

static struct auth_data auth_files[] = {
    DEFINE_AUTH_FILE("data/certs/KEK.auth", L"KEK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
    DEFINE_AUTH_FILE("data/certs/PK.auth", L"PK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
};

static void *db_setup(const MunitParameter params[], void* user_data)
{
    auth_lib_load(auth_files, ARRAY_SIZE(auth_files));
    auth_lib_initialize(auth_files, ARRAY_SIZE(auth_files));
    return NULL;
}

static void db_tear_down(void* fixture)
{
    auth_lib_deinit(auth_files, ARRAY_SIZE(auth_files));
    storage_destroy();
}

MunitTest db_tests[] = {
    { (char*)"test_db_signed_by_pk", test_db_signed_by_pk,
        db_setup, db_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_db_signed_by_kek", test_db_signed_by_kek,
        db_setup, db_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_db_append", test_db_append,
        db_setup, db_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
