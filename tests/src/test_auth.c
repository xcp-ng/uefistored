/**
 * This test suite tests the varstored-ng implementation of authenticated variables.
 *
 * For the authenticated variables specification, see the UEFI specification version  2.3.1 or greater.
 *
 */

#include <openssl/x509.h>

#include "common.h"
#include "backends/ramdb.h"
#include "edk2/secure_boot.h"
#include "log.h"
#include "uefitypes.h"
#include "uefi_guids.h"
#include "test_common.h"
#include "test_auth.h"
#include "varnames.h"
#include "xen_variable_server.h"

#define BUFSZ 128

//static const UTF16 SetupMode[] = {'S', 'e', 't', 'u', 'p', 'M', 'o', 'd', 'e', 0};
//static const UTF16 SecureBoot[] = {'S', 'e', 'c', 'u', 'r', 'e', 'B', 'o', 'o', 't', 0};

static void pre_test(void)
{
    xen_variable_server_init(NULL);
}

static void post_test(void)
{
	ramdb_destroy();
	ramdb_deinit();
	xen_variable_server_deinit();
}

static void test_setting_pk_turns_setup_mode_off(void)
{
    uint32_t attrs;
    uint8_t data;
    size_t size = sizeof(data);
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid, "keys/PK.der", 1);
    printf("status=0x%lx\n", status);
    status = get_variable(SETUP_MODE_NAME, &gEfiGlobalVariableGuid, &attrs, &size, &data);

    test(!status);
    test(data == 0);
}

/**
 * Test that the system begins in setup mode with no PK.
 */
static void test_start_in_setup_mode(void)
{
    uint32_t attrs;
    EFI_STATUS status;
    uint8_t data = 0;
    size_t size = sizeof(data);

    status = get_variable(SETUP_MODE_NAME, &gEfiGlobalVariableGuid, &attrs, &size, &data);

    DEBUG("status=0x%lx\n", status);

    test(!status);
    test(data == 1);
}

static void test_secure_boot_var_ro(void)
{
    EFI_STATUS status;
    uint8_t data;
    size_t size = sizeof(data);

    status = set_variable(SECURE_BOOT_NAME, &gEfiGlobalVariableGuid, 0x6, size, &data);
    test(status == EFI_WRITE_PROTECTED);
}

static void test_start_with_secure_boot_off(void)
{
    uint32_t attrs;
    EFI_STATUS status;
    uint8_t data = 1;
    size_t size = sizeof(data);

    status = get_variable(SECURE_BOOT_NAME, &gEfiGlobalVariableGuid, &attrs, &size, &data);
    test(!status);
    test(data == 0);
}

static void test_bad_guid(void)
{
    EFI_GUID guid;
    EFI_STATUS status;

    memset(&guid, 0, sizeof(guid));

    status = EnrollPlatformKey(&guid, &gEfiCertPkcs7Guid, "keys/PK.der", 1);

    test(status);
}

static void test_bad_cert_type_guid(void)
{
    EFI_GUID cert_guid;
    EFI_STATUS status;

    memset(&cert_guid, 0, sizeof(cert_guid));
    cert_guid.Data1 = 0xdeadbeef;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &cert_guid, "keys/PK.der", 1);

    test(status == EFI_SECURITY_VIOLATION);
}

static void test_bad_cert_but_good_guid(void)
{
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid,
                               "keys/bad_cert.txt", 1);

    test(status == EFI_SECURITY_VIOLATION);
}

static void test_set_pk_ok(void)
{
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid,
                               "keys/PK.der", 1);

    test(status == EFI_SUCCESS);
}

static void test_x509_decode(void)
{
    EFI_STATUS status;

    X509 *cert;
    uint8_t *x509;
    uint8_t **p;
    uint64_t len;

    p = &x509;
    
    status = ReadFileContent("keys/PK.der", (void**)p, &len);

    test(!status);

    cert = d2i_X509(NULL, (const unsigned char**)&x509, len);
    test(cert != NULL);

    OPENSSL_free(cert);
}

static void test_bad_attrs(void)
{
    test(0);
}

/**
 * Test that the correct timestamp parts are zero.
 */
static void test_timestamp_zero_parts(void)
{
    test(0);
}

/**
 * Test that resetting the PK with a payload with the same timestamp
 * fails.
 */
static void test_invalid_pk_reassign_timestamp(void)
{
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid, "keys/PK.der", 1);

    test(status == EFI_SUCCESS);

    /* Enroll another key, do not increment timestamp */
    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid, "keys/PK.der", 1);

    test(status == EFI_SECURITY_VIOLATION);
}

static void test_invalid_pk_reassign(void)
{
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid, "keys/PK.der", 1);

    test(status == EFI_SUCCESS);

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid, "keys/PK2.der", 2);

    test(status == EFI_SECURITY_VIOLATION);
}

void test_auth(void)
{
    DO_TEST(test_start_in_setup_mode);
    DO_TEST(test_setting_pk_turns_setup_mode_off);
    DO_TEST(test_secure_boot_var_ro);
    DO_TEST(test_start_with_secure_boot_off);
    DO_TEST(test_bad_guid);
    DO_TEST(test_bad_cert_type_guid);
    DO_TEST(test_bad_cert_but_good_guid);
    DO_TEST(test_bad_attrs);
    DO_TEST(test_set_pk_ok);
    DO_TEST(test_x509_decode);
    DO_TEST(test_timestamp_zero_parts);
    DO_TEST(test_invalid_pk_reassign_timestamp);
    DO_TEST(test_invalid_pk_reassign);
}
