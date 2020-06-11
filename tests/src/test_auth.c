/**
 * This test suite tests the varstored-ng implementation of authenticated variables.
 *
 * For the authenticated variables specification, see the UEFI specification version  2.3.1 or greater.
 *
 */


#include "uefitypes.h"
#include "common.h"
#include "xenvariable.h"
#include "test_common.h"
#include "test_auth.h"

#define BUFSZ 128

static const UTF16 SetupMode[] = {'S', 'e', 't', 'u', 'p', 'M', 'o', 'd', 'e', 0};
static const UTF16 SecureBoot[] = {'S', 'e', 'c', 'u', 'r', 'e', 'B', 'o', 'o', 't', 0};

extern const EFI_GUID gEfiCertPkcs7Guid;
extern const EFI_GUID gEfiCertX509Guid;
extern const EFI_GUID gEfiGlobalVariableGuid;

static void pre_test(void)
{
    xenvariable_init(NULL);
}

static void post_test(void)
{
	ramdb_destroy();
	ramdb_deinit();
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
void test_timebased_auth(void)
{
    EFI_STATUS status;

    status = EnrollPlatformKey(&gEfiGlobalVariableGuid, "keys/PK.der");

    test(!status);
}

void test_setting_pk_turns_setup_mode_off(void)
{
    uint32_t attrs;
    uint8_t data;
    size_t size = sizeof(data);
    int ret;
    EFI_STATUS status;

    EnrollPlatformKey(&gEfiGlobalVariableGuid, "keys/PK.der");
    status = get_variable(SetupMode, &gEfiGlobalVariableGuid, &attrs, &size, &data);

    test(!status);
    test(data == 0);
}

/**
 * Test that the system begins in setup mode with no PK.
 */
void test_start_in_setup_mode(void)
{
    uint32_t attrs;
    EFI_STATUS status;
    uint8_t data = 0;
    size_t size = sizeof(data);
    int ret;

    status = get_variable(SetupMode, &gEfiGlobalVariableGuid, &attrs, &size, &data);

    DEBUG("status=0x%lx\n", status);

    test(!status);
    test(data == 1);
}

void test_secure_boot_var_ro(void)
{
    uint32_t attrs;
    EFI_STATUS status;
    uint8_t data;
    size_t size = sizeof(data);
    int ret;

    status = set_variable(SecureBoot, &gEfiGlobalVariableGuid, 0x6, size, &data);
    test(status == EFI_WRITE_PROTECTED);
}

void test_start_with_secure_boot_off(void)
{
    uint32_t attrs;
    EFI_STATUS status;
    uint8_t data = 1;
    size_t size = sizeof(data);
    int ret;

    status = get_variable(SecureBoot, &gEfiGlobalVariableGuid, &attrs, &size, &data);
    test(!status);
    test(data == 0);
}

void test_bad_cert_type(void)
{

    uint32_t attr = EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
}

void test_auth(void)
{
    DO_TEST(test_start_in_setup_mode);
    DO_TEST(test_setting_pk_turns_setup_mode_off);
    DO_TEST(test_secure_boot_var_ro);
    DO_TEST(test_start_with_secure_boot_off);
}
