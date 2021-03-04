#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "storage.h"
#include "test_common.h"
#include "uefi/auth.h"
#include "uefi/authlib.h"
#include "uefi/guids.h"
#include "uefi/types.h"
#include "uefi/pkcs7_verify.h"
#include "uefi/image_authentication.h"

#include "munit.h"
#include "test_suites.h"

extern EFI_GUID gEfiGlobalVariableGuid;

static struct auth_data auth_files[] = {
    DEFINE_AUTH_FILE("data/certs/PK.auth", L"PK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
};

#define BUF_SIZE 4096
static uint8_t DEFAULT_PK[BUF_SIZE];

#define PK_ATTRS (EFI_VARIABLE_RUNTIME_ACCESS | \
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                  EFI_VARIABLE_NON_VOLATILE | \
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

static inline EFI_STATUS util_set_pk(void *data, size_t n)
{
    return auth_lib_process_variable(L"PK", sizeof_wchar(L"PK"), &gEfiGlobalVariableGuid,
                                     data, n, PK_ATTRS);
}

static MunitResult test_parsing_pkcs7(const MunitParameter params[], void *testdata)
{
    PKCS7 *pkcs7;

    if (file_to_buf("data/certs/nullPK.auth", DEFAULT_PK, BUF_SIZE) < 0) {
        fprintf(stderr, "failed to open data/certs/nullPK.auth\n");
        return MUNIT_ERROR;
    }

    pkcs7 = pkcs7_from_auth((EFI_VARIABLE_AUTHENTICATION_2 *)DEFAULT_PK);
    munit_assert_ptr_not_null(pkcs7);

    PKCS7_free(pkcs7);

    return MUNIT_OK;
}

static MunitResult test_parsing_pkcs7_top_cert(const MunitParameter params[], void *testdata)
{
    PKCS7 *pkcs7;
    uint8_t *top_cert_der;
    int top_cert_der_size;

    pkcs7 = pkcs7_from_auth((EFI_VARIABLE_AUTHENTICATION_2 *)DEFAULT_PK);
    top_cert_der = pkcs7_get_top_cert_der(pkcs7, &top_cert_der_size);
    munit_assert_ptr_not_null(top_cert_der);

    PKCS7_free(pkcs7);
    free(top_cert_der);

    return MUNIT_OK;
}

static MunitResult test_pk_new_cert_neq_dummy_cert(const MunitParameter params[], void *testdata)
{
    PKCS7 *pkcs7;
    uint8_t *top_cert_der = NULL;
    int top_cert_der_size;
    EFI_SIGNATURE_LIST dummy_esl;

    memset(&dummy_esl, 0, sizeof(dummy_esl));

    pkcs7 = pkcs7_from_auth((EFI_VARIABLE_AUTHENTICATION_2 *)DEFAULT_PK);
    top_cert_der = pkcs7_get_top_cert_der(pkcs7, &top_cert_der_size);

    munit_assert_false(cert_equals_esl(top_cert_der, top_cert_der_size, &dummy_esl));

    PKCS7_free(pkcs7);
    free(top_cert_der);

    return MUNIT_OK;
}

static MunitResult test_pk_new_cert_eq_old_cert(const MunitParameter params[], void *testdata)
{
    MunitResult result = MUNIT_OK;
    PKCS7 *pkcs7;
    uint8_t *top_cert_der;
    int top_cert_der_size;
    EFI_SIGNATURE_LIST *old_esl;
    uint64_t old_esl_size;
    EFI_STATUS status;

    auth_lib_load(auth_files, ARRAY_SIZE(auth_files));

    if (auth_lib_initialize(auth_files, ARRAY_SIZE(auth_files)) != EFI_SUCCESS) {
        result = MUNIT_ERROR;
        goto out;
    }

    status = auth_internal_find_variable(L"PK", sizeof_wchar(L"PK"),
                                         &gEfiGlobalVariableGuid, (void*)&old_esl,
                                         &old_esl_size);

    if (status != EFI_SUCCESS) {
        result = MUNIT_ERROR;
        goto out;
    }

    if (file_to_buf("data/certs/PK.auth", DEFAULT_PK, BUF_SIZE) < 0) {
        fprintf(stderr, "failed to open data/null.auth\n");
        result = MUNIT_ERROR;
        goto out;
    }

    pkcs7 = pkcs7_from_auth((EFI_VARIABLE_AUTHENTICATION_2 *)DEFAULT_PK);
    top_cert_der = pkcs7_get_top_cert_der(pkcs7, &top_cert_der_size);

    munit_assert_true(cert_equals_esl(top_cert_der, top_cert_der_size, old_esl));

out:
    PKCS7_free(pkcs7);
    free(top_cert_der);
    auth_lib_deinit(auth_files, ARRAY_SIZE(auth_files));

    return result;
}

static void *pk_setup(const MunitParameter params[], void* user_data)
{
    auth_lib_load(auth_files, ARRAY_SIZE(auth_files));
    auth_lib_initialize(auth_files, ARRAY_SIZE(auth_files));
    return NULL;
}

static void pk_tear_down(void* fixture)
{
    auth_lib_deinit(auth_files, ARRAY_SIZE(auth_files));
    storage_destroy();
}

static MunitResult test_null_pk(const MunitParameter params[], void *testdata)
{
    int ret;
    EFI_STATUS status;

    if ((ret = file_to_buf("data/certs/nullPK.auth", DEFAULT_PK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/nullPK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    status = util_set_pk(DEFAULT_PK, ret);

    munit_assert_uint64(status, ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_new_pk(const MunitParameter params[], void *testdata)
{
    int ret;
    EFI_STATUS status;

    if ((ret = file_to_buf("data/certs/newPK.auth", DEFAULT_PK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/newPK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    status = util_set_pk(DEFAULT_PK, ret);

    munit_assert_uint64(status, ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_new_pk_to_old_fails(const MunitParameter params[], void *testdata)
{
    int ret;
    uint8_t PK[BUF_SIZE];
    uint8_t newPK[BUF_SIZE];

    if ((ret = file_to_buf("data/certs/newPK.auth", newPK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/newPK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_pk(newPK, ret), ==, EFI_SUCCESS);

    if ((ret = file_to_buf("data/certs/PK.auth", PK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/PK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_pk(PK, ret), ==, EFI_SECURITY_VIOLATION);

    return MUNIT_OK;
}

static MunitResult test_unauthorized_sig_fails(const MunitParameter params[], void *testdata)
{
    int ret;
    uint8_t badPK[BUF_SIZE];

    if ((ret = file_to_buf("data/certs/badPK.auth", badPK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/certs/badPK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_pk(badPK, ret), ==, EFI_SECURITY_VIOLATION);

    return MUNIT_OK;
}

MunitTest pk_tests[] = {
    { (char*)"test_parsing_pkcs7", test_parsing_pkcs7,
        NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_parsing_pkcs7_top_cert", test_parsing_pkcs7_top_cert,
        NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_pk_new_cert_neq_dummy_cert", test_pk_new_cert_neq_dummy_cert,
        NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_pk_new_cert_eq_old_cert", test_pk_new_cert_eq_old_cert,
        NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_null_pk", test_null_pk,
        pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_new_pk", test_new_pk,
        pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_new_pk_to_old_fails", test_new_pk_to_old_fails,
        pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_unauthorized_sig_fails", test_unauthorized_sig_fails,
        pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};
