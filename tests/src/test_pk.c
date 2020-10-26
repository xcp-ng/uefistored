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

#include "munit.h"

static uint8_t DEFAULT_PK[] = {
#include "default_pk.txt"
};

#define BUF_SIZE 4096

#define PK_ATTRS (EFI_VARIABLE_RUNTIME_ACCESS | \
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                  EFI_VARIABLE_NON_VOLATILE | \
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

int file_to_buf(const char *fpath, uint8_t *bytes, size_t n)
{
    struct stat statbuf;
    int fd, ret;

    ret = stat(fpath, &statbuf);

    if (ret < 0)
        return ret;

    if (n < statbuf.st_size) {
        fprintf(stderr, "%s:%d: buffer not big enough, %lu required\n", __func__, __LINE__, statbuf.st_size);
        return -1;
    }

    fd = open(fpath, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "%s:%d: failed to open %s\n", __func__, __LINE__, fpath);
        return fd;
    }

    return read(fd, bytes, statbuf.st_size);
}

static inline EFI_STATUS util_set_pk(void *data, size_t n)
{
    return auth_lib_process_variable((UTF16*)L"PK",&gEfiGlobalVariableGuid,
                                       data, n, PK_ATTRS);
}

static MunitResult test_parsing_pkcs7(const MunitParameter params[], void *testdata)
{
    PKCS7 *pkcs7;

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
    uint8_t *top_cert_der;
    int top_cert_der_size;
    EFI_SIGNATURE_LIST dummy_esl;

    pkcs7 = pkcs7_from_auth((EFI_VARIABLE_AUTHENTICATION_2 *)DEFAULT_PK);
    top_cert_der = pkcs7_get_top_cert_der(pkcs7, &top_cert_der_size);

    munit_assert_false(cert_equals_esl(top_cert_der, top_cert_der_size, &dummy_esl));

    PKCS7_free(pkcs7);
    free(top_cert_der);

    return MUNIT_OK;
}

static MunitResult test_pk_new_cert_eq_old_cert(const MunitParameter params[], void *testdata)
{
    PKCS7 *pkcs7;
    uint8_t *top_cert_der;
    int top_cert_der_size;
    EFI_SIGNATURE_LIST *old_esl;
    uint64_t old_esl_size;
    EFI_STATUS status;

    storage_init();
    auth_lib_initialize();

    status = auth_internal_find_variable(L"PK",
                                         &gEfiGlobalVariableGuid, (void*)&old_esl,
                                         &old_esl_size);

    if (status != EFI_SUCCESS) {
        return MUNIT_ERROR;
    }

    pkcs7 = pkcs7_from_auth((EFI_VARIABLE_AUTHENTICATION_2 *)DEFAULT_PK);
    top_cert_der = pkcs7_get_top_cert_der(pkcs7, &top_cert_der_size);

    munit_assert_true(cert_equals_esl(top_cert_der, top_cert_der_size, old_esl));

    PKCS7_free(pkcs7);
    free(top_cert_der);
    storage_deinit();

    return MUNIT_OK;
}

static void *pk_setup(const MunitParameter params[], void* user_data)
{
    storage_init();
    auth_lib_initialize();
    return NULL;
}

static void pk_tear_down(void* fixture)
{
    storage_deinit();
}

static MunitResult test_null_pk(const MunitParameter params[], void *testdata)
{
    int ret;
    EFI_STATUS status;
    uint8_t null[BUF_SIZE];

    if ((ret = file_to_buf("data/certs/null.auth", null, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/null.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    status = util_set_pk(null, ret);

    munit_assert_uint64(status, ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_new_pk(const MunitParameter params[], void *testdata)
{
    int ret;
    EFI_STATUS status;
    uint8_t new_PK[BUF_SIZE];

    if ((ret = file_to_buf("data/certs/new_PK.auth", new_PK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/new_PK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    status = util_set_pk(new_PK, ret);

    munit_assert_uint64(status, ==, EFI_SUCCESS);

    return MUNIT_OK;
}

static MunitResult test_new_pk_to_old_fails(const MunitParameter params[], void *testdata)
{
    int ret;
    uint8_t PK[BUF_SIZE];
    uint8_t new_PK[BUF_SIZE];

    if ((ret = file_to_buf("data/certs/new_PK.auth", new_PK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/new_PK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_pk(new_PK, ret), ==, EFI_SUCCESS);

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
    uint8_t unauthorized_PK[BUF_SIZE];

    if ((ret = file_to_buf("data/certs/unauthorized_PK.auth", unauthorized_PK, BUF_SIZE)) < 0) {
        fprintf(stderr, "failed to open data/unauthorized_PK.auth: %d\n", ret);
        return MUNIT_ERROR;
    }

    munit_assert_uint64(util_set_pk(unauthorized_PK, ret), ==, EFI_SECURITY_VIOLATION);

    return MUNIT_OK;
}

MunitTest test_suite_tests[] = {
    { (char*)"test_parsing_pkcs7", test_parsing_pkcs7, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_parsing_pkcs7_top_cert", test_parsing_pkcs7_top_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_pk_new_cert_neq_dummy_cert", test_pk_new_cert_neq_dummy_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_pk_new_cert_eq_old_cert", test_pk_new_cert_eq_old_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_null_pk", test_null_pk, pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_new_pk", test_new_pk, pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_new_pk_to_old_fails", test_new_pk_to_old_fails, pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"test_unauthorized_sig_fails", test_unauthorized_sig_fails, pk_setup, pk_tear_down, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};

const MunitSuite test_suite_pk = {
  (char*) "pk/",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};
