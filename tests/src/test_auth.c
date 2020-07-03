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
#include "xenvariable.h"

#define BUFSZ 128

//static const UTF16 SetupMode[] = {'S', 'e', 't', 'u', 'p', 'M', 'o', 'd', 'e', 0};
//static const UTF16 SecureBoot[] = {'S', 'e', 'c', 'u', 'r', 'e', 'B', 'o', 'o', 't', 0};

static void pre_test(void)
{
    xenvariable_init(NULL);
}

static void post_test(void)
{
	ramdb_destroy();
	ramdb_deinit();
    xenvariable_deinit();
}

/**
 * Test that time based authentication works.
 *
 * According to the UEFI specification:

A caller that invokes the SetVariable() service with the
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute set shall do the
following prior to invoking the service:

1.    Create a descriptor
        Create an EFI_VARIABLE_AUTHENTICATION_2 descriptor where:
                - TimeStamp is set to the current time.
                - AuthInfo.CertTypeis set to EFI_CERT_TYPE_PKCS7_GUID

2.    Hash the serialization
        Hash the serialization of the values of the VariableName, VendorGuid
        and Attributesparameters of the SetVariable() call and theTimeStampcomponent of
        the EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable’s new
        value (i.e.  the Dataparameter’s new variable content).That is, digest = hash
        (VariableName, VendorGuid, Attributes, TimeStamp, DataNew_variable_content).
        The NULL character terminating the VariableName value shall not be included in
        the hash computation

3.    Sign the resulting digest
        Sign the resulting digest using a selected 

4.    Construct a DER-encoded PKCS
        Construct a DER-encoded PKCS #7 version 1.5 SignedData (see [RFC2315])
        with the signed content as follows:

	a	SignedData.version shall be set to 1
        b 	SignedData.digestAlgorithms shall contain the digest algorithm
                used when preparing the signature. Only a digest algorithm of SHA-256 is
                accepted.
        c	SignedData.contentInfo.contentType shall be set to id-data
        d	SignedData.contentInfo.content shall be absent (the content is
                provided in the Data parameter to the SetVariable() call)
	e	SignedData.certificates shall contain, at a minimum, the
                signer’s DER-encoded X.509 certificatefSignedData.crls is
                optional.gSignedData.signerInfos shall be constructed as:

		-   SignerInfo.version shall be set to 1
		-   SignerInfo.issuerAndSerial shall be present and as in the signer’s certificate
		-   SignerInfo.authenticatedAttributes shall not be present.
		-   SignerInfo.digestEncryptionAlgorithm shall be set to the
		    algorithm used to sign the data. Only a digest encryption algorithm of RSA with
		    PKCS #1 v1.5 padding (RSASSA_PKCS1-v1_5). is accepted.
		-   SiginerInfo.encryptedDigest shall be present
		-   SignerInfo.unauthenticatedAttributes shall not be present

5.    Set AuthInfo.CertData
	Set AuthInfo.CertData to the DER-encoded PKCS #7 SignedData value.

6.    Construct Data parameter
        Construct the SetVariable()’s Dataparameter by concatenating the complete,
        serialized EFI_VARIABLE_AUTHENTICATION_2 descriptor with the new value of the
        variable(DataNew_variable_content).

*/
static void test_timebased_auth(void)
{
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, &gEfiCertPkcs7Guid, "keys/PK.der", 1);

    test(!status);
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
