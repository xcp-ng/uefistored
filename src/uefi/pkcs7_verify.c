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
    if (data_size < 16 || 
        data[4] != 0x06 ||
        data[5] != 0x09 ||
        memcmp(data + 6, mOidValue, sizeof(mOidValue)) != 0 ||
        data[15] != 0xA0 ||
        data[16] != 0x82)
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
uint8_t *wrap_with_content_info(const uint8_t *data, uint32_t size,  uint32_t *wrapped_size)
{
    uint8_t *wrapped;

    if (!data)
        return NULL;

    if (is_content_info(data, size)) {
        wrapped = malloc(size);
        if (!wrapped)
            return NULL;

        memcpy(wrapped, data, size);
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

/**
  Pop single certificate from STACK_OF(X509).

  If X509Stack, Cert, or CertSize is NULL, then return false.

  @param[in]  X509Stack       Pointer to a X509 stack object.
  @param[out] Cert            Pointer to a X509 certificate.
  @param[out] CertSize        Length of output X509 certificate in bytes.

  @retval     true            The X509 stack pop succeeded.
  @retval     false           The pop operation failed.

**/
bool X509PopCertificate(void *X509Stack, uint8_t **Cert, uint64_t *CertSize)
{
    BIO *CertBio;
    X509 *X509Cert;
    STACK_OF(X509) * CertStack;
    bool Status;
    int32_t Result;
    BUF_MEM *Ptr;
    int32_t Length;
    void *Buffer;

    Status = false;

    if ((X509Stack == NULL) || (Cert == NULL) || (CertSize == NULL)) {
        return Status;
    }

    CertStack = (STACK_OF(X509) *)X509Stack;

    X509Cert = sk_X509_pop(CertStack);

    if (X509Cert == NULL) {
        return Status;
    }

    Buffer = NULL;

    CertBio = BIO_new(BIO_s_mem());
    if (CertBio == NULL) {
        return Status;
    }

    Result = i2d_X509_bio(CertBio, X509Cert);
    if (Result == 0) {
        goto _Exit;
    }

    BIO_get_mem_ptr(CertBio, &Ptr);
    Length = (int32_t)(Ptr->length);
    if (Length <= 0) {
        goto _Exit;
    }

    Buffer = malloc(Length);
    if (Buffer == NULL) {
        goto _Exit;
    }

    Result = BIO_read(CertBio, Buffer, Length);
    if (Result != Length) {
        goto _Exit;
    }

    *Cert = Buffer;
    *CertSize = Length;

    Status = true;

_Exit:

    BIO_free(CertBio);

    if (!Status && (Buffer != NULL)) {
        free(Buffer);
    }

    return Status;
}

/*
 * Get the signer's certificates from PKCS#7 signed data.
 * Adapted from edk2.
 *
 * The caller is responsible for free the pkcs7 context and the stack of certs
 * (but not the certs themselves). The certs should not be used after the
 * context is freed.
 */
EFI_STATUS pkcs7_get_signers(const uint8_t *p7data, uint64_t p7_len,
                             PKCS7 **pkcs7, STACK_OF(X509) **certs)
{
    const uint8_t *ptr;

    ptr = p7data;
    *pkcs7 = d2i_PKCS7(NULL, &ptr, (int)p7_len);
    if (!*pkcs7)
        return EFI_SECURITY_VIOLATION;

    if (!PKCS7_type_is_signed(*pkcs7)) {
        PKCS7_free(*pkcs7);
        *pkcs7 = NULL;
        return EFI_SECURITY_VIOLATION;
    }

    *certs = PKCS7_get0_signers(*pkcs7, NULL, PKCS7_BINARY);
    if (!*certs) {
        PKCS7_free(*pkcs7);
        *pkcs7 = NULL;
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
    pkcs7 = d2i_PKCS7(NULL, (const unsigned char**)&temp, (int)sig_data_size);

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
    STACK_OF(X509) *certs;

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

/**
  Get the signer's certificates from PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard". The input signed data could be wrapped
  in a ContentInfo structure.

  If P7Data, SignerCerts, SignerCertsCount, TrustedCert is NULL, then
  return false. If P7Length overflow, then return false.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] SignerCerts    Pointer to Signer's certificates retrieved from P7Data.
                           It's caller's responsibility to free the buffer with
                           Pkcs7FreeSigners().
                           This data structure is EFI_CERT_STACK type.
  @param[out] SignerCertsCount  Length of signer's certificates in bytes.
  @param[out] TrustedCert  Pointer to a trusted certificate from Signer's certificates.
                           It's caller's responsibility to free the buffer with
                           Pkcs7FreeSigners().

  @retval  true            The operation is finished successfully.
  @retval  false           Error occurs during the operation.

**/
bool Pkcs7GetSigners(const uint8_t *P7Data, uint64_t P7Length,
                     STACK_OF(X509) **SignerCerts, uint64_t *SignerCertsCount)
{
    PKCS7 *Pkcs7 = NULL;
    STACK_OF(X509) *Stack = NULL;
    const uint8_t *Temp;

    if (!SignerCerts || !SignerCertsCount)
        return false;

    Temp = P7Data;
    Pkcs7 = d2i_PKCS7(NULL, &Temp, (int)P7Length);
    if (Pkcs7 == NULL) {
        DDEBUG("Pkcs7 == NULL\n");
        return false;
    }

    //
    // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
    //
    if (!PKCS7_type_is_signed(Pkcs7)) {
        DDEBUG("Pkcs7 not signed\n");
        PKCS7_free(Pkcs7);
        return false;
    }

    Stack = PKCS7_get0_signers(Pkcs7, NULL, PKCS7_BINARY);
    if (Stack == NULL) {
        PKCS7_free(Pkcs7);
        DDEBUG("PKCS7_get0_signers failed\n");
        return false;
    }

    *SignerCerts = Stack;
    *SignerCertsCount = sk_X509_num(*SignerCerts);

    PKCS7_free(Pkcs7);

    return true;
}

/**
  Wrap function to use free() to free allocated memory for certificates.

  @param[in]  Certs        Pointer to the certificates to be freed.

**/
void Pkcs7FreeSigners(X509 *Certs)
{
    if (Certs == NULL) {
        return;
    }

    free(Certs);
}

#ifndef X509_V_FLAG_NO_CHECK_TIME
#define OPENSSL_NO_CHECK_TIME 0

/*
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
static int
X509_verify_cb(int status, X509_STORE_CTX *context)
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

        CRYPTO_w_lock (CRYPTO_LOCK_X509_STORE);

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

        CRYPTO_w_unlock (CRYPTO_LOCK_X509_STORE);
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

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  InData       Pointer to the content to be verified.
  @param[in]  DataLength   Length of InData in bytes.

  @retval  true  The specified PKCS#7 signed data is valid.
  @retval  false Invalid PKCS#7 signed data.

**/
bool Pkcs7Verify(const uint8_t *P7Data, uint64_t P7Length,
                 X509 *TrustedCert,
                 const uint8_t *InData, uint64_t DataLength)
{
    PKCS7 *Pkcs7;
    BIO *DataBio;
    bool Status;
    X509_STORE *CertStore;
    uint8_t *SignedData = NULL;
    const uint8_t *Temp;
    uint32_t SignedDataSize;

    //
    // Check input parameters.
    //
    if (P7Data == NULL || InData == NULL ||
        P7Length > INT_MAX || DataLength > INT_MAX) {
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

    //
    // Retrieve PKCS#7 Data (DER encoding)
    //
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
    X509_STORE_set_flags(CertStore,
                         X509_V_FLAG_PARTIAL_CHAIN);

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
