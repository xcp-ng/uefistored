#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>

#include "log.h"
#include "uefi/auth.h"
#include "uefi/guids.h"
#include "uefi/utils.h"
#include "uefi/image_authentication.h"
#include "uefi/types.h"
#include "openssl_custom.h"

uint8_t mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

uint8_t *X509_to_buf(X509 *cert, int *len)
{
    uint8_t *ptr, *buf;

    if (!cert || !len)
        return NULL;

    *len = i2d_X509(cert, NULL);
    buf = malloc(*len);
    if (!buf)
        return NULL;
    ptr = buf;
    i2d_X509(cert, &ptr);

    return buf;
}

/**
 * Return true if data points to a ContentInfo structure, otherwise return false.
 */
bool is_content_info(const uint8_t *data, size_t data_size)
{
    if (data_size < 16 || data[4] != 0x06 || data[5] != 0x09 ||
        memcmp(data + 6, mOidValue, sizeof(mOidValue)) != 0 ||
        data[15] != 0xA0 || data[16] != 0x82)
        return false;

    return true;
}

/**
 * Wrap SignedData in a ContentInfo.
 *
 * Users may choose SignedData alone or wrapped with a ContentInfo.  OpenSSL
 * only accepts the ContentInfo form for d2i_PKCS7, so call this to ensure
 * it is wrapped prior to passing to OpenSSL.
 *
 * The return data must be freed by caller.
 *
 * Based on tianocore/edk2.
 */
uint8_t *wrap_with_content_info(const uint8_t *data, uint32_t size,
                                uint32_t *wrapped_size)
{
    uint8_t *wrapped;

    if (!data)
        return NULL;

    if (is_content_info(data, size)) {
        wrapped = malloc(size);
        if (!wrapped) {
            *wrapped_size = 0;
            return NULL;
        }

        memcpy(wrapped, data, size);
        *wrapped_size = size;
        return wrapped;
    }

    /*
     * Wrap PKCS#7 signeddata to a ContentInfo structure - add a header in 19
     * bytes.
     */
    *wrapped_size = size + 19;
    wrapped = malloc(*wrapped_size);

    if (!wrapped) {
        *wrapped_size = 0;
        return NULL;
    }

    /*
     * Part1: 0x30, 0x82.
     */
    wrapped[0] = 0x30;
    wrapped[1] = 0x82;

    /*
     * Part2: Length1 = P7Length + 19 - 4, in big endian.
     */
    wrapped[2] = (uint8_t)(((uint16_t)(*wrapped_size - 4)) >> 8);
    wrapped[3] = (uint8_t)(((uint16_t)(*wrapped_size - 4)) & 0xff);

    /*
     *  Part3: 0x06, 0x09.
     */
    wrapped[4] = 0x06;
    wrapped[5] = 0x09;

    /*
     * Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02.
     */
    memcpy(wrapped + 6, mOidValue, sizeof(mOidValue));

    /*
     * Part5: 0xA0, 0x82.
     */
    wrapped[15] = 0xA0;
    wrapped[16] = 0x82;

    /*
     * Part6: Length2 = P7Length, in big endian.
     */
    wrapped[17] = (uint8_t)(((uint16_t)size) >> 8);
    wrapped[18] = (uint8_t)(((uint16_t)size) & 0xff);

    /*
     * Part7: P7Data.
     */
    memcpy(wrapped + 19, data, size);
    return wrapped;
}

/*
 * Get the signer's certificates from PKCS#7 signed data.
 * Adapted from edk2.
 *
 * The caller is responsible for free the pkcs7 context and the stack of certs
 * (but not the certs themselves). The certs should not be used after the
 * context is freed.
 */
EFI_STATUS pkcs7_get_signers(PKCS7 *pkcs7, STACK_OF(X509) **certs)
{
    if (!pkcs7)
        return EFI_SECURITY_VIOLATION;

    if (!PKCS7_type_is_signed(pkcs7)) {
        return EFI_SECURITY_VIOLATION;
    }

    *certs = PKCS7_get0_signers(pkcs7, NULL, PKCS7_BINARY);
    if (!*certs) {
        return EFI_SECURITY_VIOLATION;
    }

    return EFI_SUCCESS;
}

/**
 * Extract OpenSSL PKCS7 from EFI_VARIABLE_AUTHENTICATION_2.
 */
PKCS7 *pkcs7_from_auth(EFI_VARIABLE_AUTHENTICATION_2 *auth)
{
    PKCS7 *pkcs7 = NULL;
    uint8_t *sig_data;
    uint32_t sig_data_size;
    unsigned char *temp;

    if (!auth) {
        return NULL;
    }

    sig_data = auth->AuthInfo.CertData;
    sig_data_size = auth->AuthInfo.Hdr.dwLength -
                    (uint32_t)(OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData));

    if (sig_data_size == 0) {
        ERROR("size=0, EFI_VARIABLE_AUTHENTICATION_2 contains no SignedData cert\n");
        return NULL;
    }

    sig_data = wrap_with_content_info(sig_data, sig_data_size, &sig_data_size);

    if (!sig_data) {
        ERROR("failed to wrap with ContentInfo\n");
        return NULL;
    }

    temp = sig_data;
    pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&temp, (int)sig_data_size);

    if (pkcs7 == NULL) {
        ERROR("%s\n", ERR_error_string(ERR_get_error(), NULL));
        ERROR("Failed to parse EFI_VARIABLE_AUTHENTICATION_2 SignedData cert\n");
        return NULL;
    }

    if (!PKCS7_type_is_signed(pkcs7)) {
        ERROR("EFI_VARIABLE_AUTHENTICATION_2 SignedData was not signed\n");
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (sig_data != auth->AuthInfo.CertData)
        free(sig_data);

    return pkcs7;
}

X509 *pkcs7_get_top_cert(PKCS7 *pkcs7)
{
    STACK_OF(X509) * certs;

    certs = PKCS7_get0_signers(pkcs7, NULL, PKCS7_BINARY);

    if (!certs)
        return NULL;

    return sk_X509_value(certs, sk_X509_num(certs) - 1);
}

uint8_t *pkcs7_get_top_cert_der(PKCS7 *pkcs7, int *top_cert_der_size)
{
    X509 *top_cert = pkcs7_get_top_cert(pkcs7);

    if (!top_cert)
        return NULL;

    return X509_to_buf(top_cert, top_cert_der_size);
}

#ifndef X509_V_FLAG_NO_CHECK_TIME
#define OPENSSL_NO_CHECK_TIME 0

/*
 * Borrowed from varstored.
 *
 * Verification callback function to override the existing callbacks in
 * OpenSSL.  This is required due to the lack of X509_V_FLAG_NO_CHECK_TIME in
 * OpenSSL 1.0.2.  This function has been taken directly from an older version
 * of edk2 and been to use X509_V_ERR_CERT_HAS_EXPIRED and
 * X509_V_ERR_CERT_NOT_YET_VALID since verification of the timestamps in
 * certificates is not typically done in firmware due to untrustworthy system
 * time. This part was taken from a patch sent to the edk2 mailing list by
 * David Woodhouse entitled "CryptoPkg: Remove OpenSSL hack and manually ignore
 * validity time range".
 */
static int X509_verify_cb(int status, X509_STORE_CTX *context)
{
    X509_OBJECT *obj = NULL;
    int error;
    int index;
    int count;

    error = X509_STORE_CTX_get_error(context);

    if ((error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) ||
        (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
        obj = malloc(sizeof(*obj));
        if (!obj)
            return 0;

        obj->type = X509_LU_X509;
        obj->data.x509 = context->current_cert;

        CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);

        if (X509_OBJECT_retrieve_match(context->ctx->objs, obj)) {
            status = 1;
        } else {
            if (error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
                count = sk_X509_num(context->chain);
                for (index = 0; index < count; index++) {
                    obj->data.x509 = sk_X509_value(context->chain, index);
                    if (X509_OBJECT_retrieve_match(context->ctx->objs, obj)) {
                        status = 1;
                        break;
                    }
                }
            }
        }

        CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
    }

    if ((error == X509_V_ERR_CERT_UNTRUSTED) ||
        (error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) ||
        (error == X509_V_ERR_CERT_HAS_EXPIRED) ||
        (error == X509_V_ERR_CERT_NOT_YET_VALID))
        status = 1;

    free(obj);

    return status;
}
#else
#define OPENSSL_NO_CHECK_TIME X509_V_FLAG_NO_CHECK_TIME
#endif

/**
  Verifies the validity of a PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard". The input signed data could be wrapped
  in a ContentInfo structure.

  If P7Data, TrustedCert or InData is NULL, then return false.
  If P7Length or DataLength overflow, then return false.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @parm P7Data      Pointer to the PKCS#7 message to verify.
  @parm P7Length    Length of the PKCS#7 message in bytes.
  @parm TrustedCert Pointer to a trusted/root certificate encoded in DER, which
                    is used for certificate chain verification.
  @parm InData      Pointer to the content to be verified.
  @parm DataLength  Length of InData in bytes.

  @return  true  The specified PKCS#7 signed data is valid.
  @return  false Invalid PKCS#7 signed data.
**/
bool Pkcs7Verify(const uint8_t *P7Data, uint64_t P7Length, X509 *TrustedCert,
                 const uint8_t *InData, uint64_t DataLength)
{
    PKCS7 *Pkcs7;
    BIO *DataBio;
    bool Status;
    X509_STORE *CertStore;
    uint8_t *SignedData = NULL;
    const uint8_t *Temp;
    uint32_t SignedDataSize;

    if (P7Data == NULL || InData == NULL || P7Length > INT_MAX ||
        DataLength > INT_MAX) {
        return false;
    }

    Pkcs7 = NULL;
    DataBio = NULL;
    CertStore = NULL;

    if (EVP_add_digest(EVP_sha256()) == 0) {
        return false;
    }

    SignedData = wrap_with_content_info(P7Data, P7Length, &SignedDataSize);

    if (!SignedData) {
        ERROR("failed to wrap with ContentInfo\n");
        return false;
    }

    Status = false;

    /*
     * Retrieve PKCS#7 Data (DER encoding)
     */
    if (SignedDataSize > INT_MAX) {
        goto _Exit;
    }

    Temp = SignedData;
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
    if (Pkcs7 == NULL) {
        goto _Exit;
    }

    //
    // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
    //
    if (!PKCS7_type_is_signed(Pkcs7)) {
        goto _Exit;
    }

    //
    // Setup X509 Store for trusted certificate
    //
    CertStore = X509_STORE_new();
    if (CertStore == NULL) {
        goto _Exit;
    }

#ifndef X509_V_FLAG_NO_CHECK_TIME
    CertStore->verify_cb = X509_verify_cb;
#endif

    if (!(X509_STORE_add_cert(CertStore, TrustedCert))) {
        goto _Exit;
    }

    //
    // For generic PKCS#7 handling, InData may be NULL if the content is present
    // in PKCS#7 structure. So ignore NULL checking here.
    //
    DataBio = BIO_new(BIO_s_mem());
    if (DataBio == NULL) {
        goto _Exit;
    }

    if (BIO_write(DataBio, InData, (int)DataLength) <= 0) {
        goto _Exit;
    }

    //
    // Allow partial certificate chains, terminated by a non-self-signed but
    // still trusted intermediate certificate. Also disable time checks.
    //
    X509_STORE_set_flags(CertStore, X509_V_FLAG_PARTIAL_CHAIN);

    //
    // OpenSSL PKCS7 Verification by default checks for SMIME (email signing) and
    // doesn't support the extended key usage for Authenticode Code Signing.
    // Bypass the certificate purpose checking by enabling any purposes setting.
    //
    X509_STORE_set_purpose(CertStore, X509_PURPOSE_ANY);

    //
    // Verifies the PKCS#7 signedData structure
    //
    Status = (bool)PKCS7_verify(Pkcs7, NULL, CertStore, DataBio, NULL,
                                PKCS7_BINARY);

_Exit:
    //
    // Release Resources
    //
    BIO_free(DataBio);
    X509_STORE_free(CertStore);
    PKCS7_free(Pkcs7);

    if (SignedData)
        free(SignedData);

    return Status;
}

bool pkcs7_verify(PKCS7 *pkcs7, X509 *trusted_cert, const uint8_t *new_data,
                  uint64_t new_data_size)
{
    BIO *bio = NULL;
    bool status;
    X509_STORE *store;

    if (new_data == NULL || new_data_size > INT_MAX)
        return false;

    if (!pkcs7 || !trusted_cert) {
        ERROR("null args\n");
        return  false;
    }

    if (EVP_add_digest(EVP_sha256()) == 0) {
        ERROR("Failed to add sha256 to OpenSSL EVP\n");
        return false;
    }

    status = false;

    /*
     * Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
     */
    if (!PKCS7_type_is_signed(pkcs7)) {
        ERROR("PKCS7 is not signed!\n");
        return false;
    }

    /*
     * Setup X509 Store for trusted certificate
     */
    store = X509_STORE_new();

    if (store == NULL)
        return false;

#ifndef X509_V_FLAG_NO_CHECK_TIME
    store->verify_cb = X509_verify_cb;
#endif

    if (!(X509_STORE_add_cert(store, trusted_cert))) {
        ERROR("Failed to add cert\n");
        goto err;
    }

    /*
     * For generic PKCS#7 handling, new_data may be NULL if the content is present
     * in PKCS#7 structure. So ignore NULL checking here.
     */
    bio = BIO_new(BIO_s_mem());

    if (bio == NULL) {
        ERROR("Failed to allocated OpenSSL BIO\n");
        goto err;
    }

    if (BIO_write(bio, new_data, (int)new_data_size) != new_data_size) {
        ERROR("Failed to write OpenSSL BIO\n");
        goto err;
    }

    /*
     * Allow partial certificate chains, terminated by a non-self-signed but
     * still trusted intermediate certificate. Also disable time checks.
    */
    X509_STORE_set_flags(store,
                         X509_V_FLAG_PARTIAL_CHAIN | OPENSSL_NO_CHECK_TIME);

    /*
     * OpenSSL PKCS7 Verification by default checks for SMIME (email signing) and
     * doesn't support the extended key usage for Authenticode Code Signing.
     * Bypass the certificate purpose checking by enabling any purposes setting.
     */
    X509_STORE_set_purpose(store, X509_PURPOSE_ANY);

    /*
     * Verifies the PKCS#7 signedData structure
     */
    status = (bool)PKCS7_verify(pkcs7, NULL, store, bio, NULL, PKCS7_BINARY);

    if (!status) {
        ERROR("PKCS7_verify() failed\n");
        ERR_print_errors_fp(stderr);
        ERR_load_crypto_strings();
        ERR_free_strings();
    }

err:
    //
    // Release Resources
    //
    if (bio) {
        BIO_free(bio);
    }
    X509_STORE_free(store);

    return status;
}
