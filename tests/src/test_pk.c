#include <stdlib.h>

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

    munit_assert_false(pk_new_cert_valid(top_cert_der, top_cert_der_size, &dummy_esl));

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

    munit_assert_true(pk_new_cert_valid(top_cert_der, top_cert_der_size, old_esl));

    PKCS7_free(pkcs7);
    free(top_cert_der);
    storage_deinit();

    return MUNIT_OK;
}

MunitTest test_suite_tests[] = {
    { (char*)"parsing_pkcs7", test_parsing_pkcs7, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"parsing_pkcs7_top_cert", test_parsing_pkcs7_top_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"pk_new_cert_neq_dummy_cert", test_pk_new_cert_neq_dummy_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"pk_new_cert_eq_old_cert", test_pk_new_cert_eq_old_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};

const MunitSuite test_suite_pk = {
  (char*) "pk/",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};
