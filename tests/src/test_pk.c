#include <stdlib.h>

#include "uefi/types.h"
#include "uefi/auth.h"
#include "uefi/pkcs7_verify.h"

#include "munit.h"

static const uint8_t DEFAULT_PK[] = {
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

MunitTest test_suite_tests[] = {
    { (char*)"parsing_pkcs7", test_parsing_pkcs7, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { (char*)"parsing_pkcs7_top_cert_der", test_parsing_pkcs7_top_cert, NULL, NULL, MUNIT_SUITE_OPTION_NONE, NULL },
    { 0 }
};

const MunitSuite test_suite_pk = {
  (char*) "pk/",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};
