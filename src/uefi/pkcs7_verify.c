/** @file
  PKCS#7 SignedData Verification Wrapper Implementation over OpenSSL.

  Caution: This module requires additional review when modified.
  This library will have external input - signature (e.g. UEFI Authenticated
  Variable). It may by input in SMM mode.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  WrapPkcs7Data(), Pkcs7GetSigners(), Pkcs7Verify() will get UEFI Authenticated
  Variable and will do basic check for data structure.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>

#include "log.h"
#include "uefi/utils.h"
#include "uefi/types.h"
#include "openssl_custom.h"

#define TRACE() DDEBUG("\n")

uint8_t mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

uint8_t *X509_to_buf(X509 *cert, int *len)
{
    uint8_t *ptr, *buf;

    *len = i2d_X509(cert, NULL);
    buf = malloc(*len);
    if (!buf)
        return NULL;
    ptr = buf;
    i2d_X509(cert, &ptr);

    return buf;
}

/**
  Check input P7Data is a wrapped ContentInfo structure or not. If not construct
  a new structure to wrap P7Data.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] WrapFlag     If true P7Data is a ContentInfo structure, otherwise
                           return false.
  @param[out] WrapData     If return status of this function is true:
                           1) when WrapFlag is true, pointer to P7Data.
                           2) when WrapFlag is false, pointer to a new ContentInfo
                           structure. It's caller's responsibility to free this
                           buffer.
  @param[out] WrapDataSize Length of ContentInfo structure in bytes.

  @retval     true         The operation is finished successfully.
  @retval     false        The operation is failed due to lack of resources.

**/
bool WrapPkcs7Data(const uint8_t *P7Data, uint64_t P7Length, bool *WrapFlag,
                   uint8_t **WrapData, uint64_t *WrapDataSize)
{
    bool Wrapped;
    uint8_t *SignedData;

    //
    // Check whether input P7Data is a wrapped ContentInfo structure or not.
    //
    Wrapped = false;
    if ((P7Data[4] == 0x06) && (P7Data[5] == 0x09)) {
        if (memcmp(P7Data + 6, mOidValue, sizeof(mOidValue)) == 0) {
            if ((P7Data[15] == 0xA0) && (P7Data[16] == 0x82)) {
                Wrapped = true;
            }
        }
    }

    if (Wrapped) {
        *WrapData = (uint8_t *)P7Data;
        *WrapDataSize = P7Length;
    } else {
        //
        // Wrap PKCS#7 signeddata to a ContentInfo structure - add a header in 19 bytes.
        //
        *WrapDataSize = P7Length + 19;
        *WrapData = malloc(*WrapDataSize);
        if (*WrapData == NULL) {
            *WrapFlag = Wrapped;
            return false;
        }

        SignedData = *WrapData;

        //
        // Part1: 0x30, 0x82.
        //
        SignedData[0] = 0x30;
        SignedData[1] = 0x82;

        //
        // Part2: Length1 = P7Length + 19 - 4, in big endian.
        //
        SignedData[2] = (uint8_t)(((uint16_t)(*WrapDataSize - 4)) >> 8);
        SignedData[3] = (uint8_t)(((uint16_t)(*WrapDataSize - 4)) & 0xff);

        //
        // Part3: 0x06, 0x09.
        //
        SignedData[4] = 0x06;
        SignedData[5] = 0x09;

        //
        // Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02.
        //
        memcpy(SignedData + 6, mOidValue, sizeof(mOidValue));

        //
        // Part5: 0xA0, 0x82.
        //
        SignedData[15] = 0xA0;
        SignedData[16] = 0x82;

        //
        // Part6: Length2 = P7Length, in big endian.
        //
        SignedData[17] = (uint8_t)(((uint16_t)P7Length) >> 8);
        SignedData[18] = (uint8_t)(((uint16_t)P7Length) & 0xff);

        //
        // Part7: P7Data.
        //
        memcpy(SignedData + 19, P7Data, P7Length);
    }

    *WrapFlag = Wrapped;
    return true;
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

/**
  Retrieves all embedded certificates from PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard", and outputs two certificate lists chained and
  unchained to the signer's certificates.
  The input signed data could be wrapped in a ContentInfo structure.

  @param[in]  P7Data            Pointer to the PKCS#7 message.
  @param[in]  P7Length          Length of the PKCS#7 message in bytes.
  @param[out] SignerChainCerts  Pointer to the certificates list chained to signer's
                                certificate. It's caller's responsibility to free the buffer
                                with Pkcs7FreeSigners().
                                This data structure is EFI_CERT_STACK type.
  @param[out] ChainLength       Length of the chained certificates list buffer in bytes.
  @param[out] UnchainCerts      Pointer to the unchained certificates lists. It's caller's
                                responsibility to free the buffer with Pkcs7FreeSigners().
                                This data structure is EFI_CERT_STACK type.
  @param[out] UnchainLength     Length of the unchained certificates list buffer in bytes.

  @retval  true         The operation is finished successfully.
  @retval  false        Error occurs during the operation.

**/
bool Pkcs7GetCertificatesList(const uint8_t *P7Data, uint64_t P7Length,
                              uint8_t **SignerChainCerts, uint64_t *ChainLength,
                              uint8_t **UnchainCerts, uint64_t *UnchainLength)
{
    bool Status;
    uint8_t *NewP7Data;
    uint64_t NewP7Length;
    bool Wrapped;
    uint8_t Index;
    PKCS7 *Pkcs7;
    X509_STORE_CTX *CertCtx;
    STACK_OF(X509) * CtxChain;
    STACK_OF(X509) * CtxUntrusted;
    X509 *CtxCert;
    STACK_OF(X509) * Signers;
    X509 *Signer;
    X509 *Cert;
    X509 *Issuer;
    X509_NAME *IssuerName;
    uint8_t *CertBuf;
    uint8_t *OldBuf;
    uint64_t BufferSize;
    uint64_t OldSize;
    uint8_t *SingleCert;
    uint64_t CertSize;

    //
    // Initializations
    //
    Status = false;
    NewP7Data = NULL;
    Pkcs7 = NULL;
    CertCtx = NULL;
    CtxChain = NULL;
    CtxCert = NULL;
    CtxUntrusted = NULL;
    Cert = NULL;
    SingleCert = NULL;
    CertBuf = NULL;
    OldBuf = NULL;
    Signers = NULL;

    memset(&CertCtx, 0, sizeof(CertCtx));

    //
    // Parameter Checking
    //
    if ((P7Data == NULL) || (SignerChainCerts == NULL) ||
        (ChainLength == NULL) || (UnchainCerts == NULL) ||
        (UnchainLength == NULL) || (P7Length > INT_MAX)) {
        return Status;
    }

    *SignerChainCerts = NULL;
    *ChainLength = 0;
    *UnchainCerts = NULL;
    *UnchainLength = 0;

    //
    // Construct a new PKCS#7 data wrapping with ContentInfo structure if needed.
    //
    Status =
            WrapPkcs7Data(P7Data, P7Length, &Wrapped, &NewP7Data, &NewP7Length);
    if (!Status || (NewP7Length > INT_MAX)) {
        goto _Error;
    }

    //
    // Decodes PKCS#7 SignedData
    //
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&NewP7Data,
                      (int)NewP7Length);
    if ((Pkcs7 == NULL) || (!PKCS7_type_is_signed(Pkcs7))) {
        goto _Error;
    }

    //
    // Obtains Signer's Certificate from PKCS#7 data
    // NOTE: Only one signer case will be handled in this function, which means SignerInfos
    //       should include only one signer's certificate.
    //
    Signers = PKCS7_get0_signers(Pkcs7, NULL, PKCS7_BINARY);
    if ((Signers == NULL) || (sk_X509_num(Signers) != 1)) {
        goto _Error;
    }
    Signer = sk_X509_value(Signers, 0);

    CertCtx = X509_STORE_CTX_new();
    if (CertCtx == NULL) {
        goto _Error;
    }
    if (!X509_STORE_CTX_init(CertCtx, NULL, Signer, Pkcs7->d.sign->cert)) {
        goto _Error;
    }
    //
    // Initialize Chained & Untrusted stack
    //
    CtxChain = X509_STORE_CTX_get1_chain(CertCtx);
    CtxCert = X509_STORE_CTX_get_current_cert(CertCtx);
    if (CtxChain == NULL) {
        if (((CtxChain = sk_X509_new_null()) == NULL) ||
            (!sk_X509_push(CtxChain, CtxCert))) {
            goto _Error;
        }
    }
    CtxUntrusted = X509_STORE_CTX_get0_untrusted(CertCtx);
    if (CtxUntrusted != NULL) {
        (void)sk_X509_delete_ptr(CtxUntrusted, Signer);
    }

    //
    // Build certificates stack chained from Signer's certificate.
    //
    Cert = Signer;
    for (;;) {
        //
        // Self-Issue checking
        //
        Issuer = NULL;
        if (X509_STORE_CTX_get1_issuer(&Issuer, CertCtx, Cert) == 1) {
            if (X509_cmp(Issuer, Cert) == 0) {
                break;
            }
        }

        //
        // Found the issuer of the current certificate
        //
        if (CtxUntrusted != NULL) {
            Issuer = NULL;
            IssuerName = X509_get_issuer_name(Cert);
            Issuer = X509_find_by_subject(CtxUntrusted, IssuerName);
            if (Issuer != NULL) {
                if (!sk_X509_push(CtxChain, Issuer)) {
                    goto _Error;
                }
                (void)sk_X509_delete_ptr(CtxUntrusted, Issuer);

                Cert = Issuer;
                continue;
            }
        }

        break;
    }

    //
    // Converts Chained and Untrusted Certificate to Certificate Buffer in following format:
    //      uint8_t  CertNumber;
    //      uint32_t Cert1Length;
    //      uint8_t  Cert1[];
    //      uint32_t Cert2Length;
    //      uint8_t  Cert2[];
    //      ...
    //      uint32_t CertnLength;
    //      uint8_t  Certn[];
    //

    if (CtxChain != NULL) {
        BufferSize = sizeof(uint8_t);
        CertBuf = NULL;

        for (Index = 0;; Index++) {
            Status = X509PopCertificate(CtxChain, &SingleCert, &CertSize);
            if (!Status) {
                break;
            }

            OldSize = BufferSize;
            OldBuf = CertBuf;
            BufferSize = OldSize + CertSize + sizeof(uint32_t);
            CertBuf = malloc(BufferSize);

            if (CertBuf == NULL) {
                Status = false;
                goto _Error;
            }
            if (OldBuf != NULL) {
                memcpy(CertBuf, OldBuf, OldSize);
                free(OldBuf);
                OldBuf = NULL;
            }

            WriteUnaligned32((uint32_t *)(CertBuf + OldSize),
                             (uint32_t)CertSize);
            memcpy(CertBuf + OldSize + sizeof(uint32_t), SingleCert, CertSize);

            free(SingleCert);
            SingleCert = NULL;
        }

        if (CertBuf != NULL) {
            //
            // Update CertNumber.
            //
            CertBuf[0] = Index;

            *SignerChainCerts = CertBuf;
            *ChainLength = BufferSize;
        }
    }

    if (CtxUntrusted != NULL) {
        BufferSize = sizeof(uint8_t);
        CertBuf = NULL;

        for (Index = 0;; Index++) {
            Status = X509PopCertificate(CtxUntrusted, &SingleCert, &CertSize);
            if (!Status) {
                break;
            }

            OldSize = BufferSize;
            OldBuf = CertBuf;
            BufferSize = OldSize + CertSize + sizeof(uint32_t);
            CertBuf = malloc(BufferSize);

            if (CertBuf == NULL) {
                Status = false;
                goto _Error;
            }
            if (OldBuf != NULL) {
                memcpy(CertBuf, OldBuf, OldSize);
                free(OldBuf);
                OldBuf = NULL;
            }

            WriteUnaligned32((uint32_t *)(CertBuf + OldSize),
                             (uint32_t)CertSize);
            memcpy(CertBuf + OldSize + sizeof(uint32_t), SingleCert, CertSize);

            free(SingleCert);
            SingleCert = NULL;
        }

        if (CertBuf != NULL) {
            //
            // Update CertNumber.
            //
            CertBuf[0] = Index;

            *UnchainCerts = CertBuf;
            *UnchainLength = BufferSize;
        }
    }

    Status = true;

_Error:
    if (CtxChain) {
        sk_X509_pop_free(CtxChain, X509_free);
    }

    if (CtxCert) {
        sk_X509_pop_free(CtxChain, X509_free);
    }

    //
    // Release Resources.
    //
    if (!Wrapped && (NewP7Data != NULL)) {
        free(NewP7Data);
    }

    if (Pkcs7 != NULL) {
        PKCS7_free(Pkcs7);
    }
    sk_X509_free(Signers);

    if (CertCtx != NULL) {
        X509_STORE_CTX_cleanup(CertCtx);
        X509_STORE_CTX_free(CertCtx);
    }

    if (SingleCert != NULL) {
        free(SingleCert);
    }

    if (OldBuf != NULL) {
        free(OldBuf);
    }

    if (!Status && (CertBuf != NULL)) {
        free(CertBuf);
        *SignerChainCerts = NULL;
        *UnchainCerts = NULL;
    }

    return Status;
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
    uint8_t *SignedData;
    const uint8_t *Temp;
    uint64_t SignedDataSize;
    bool Wrapped;
    uint8_t *buf;
    int len;

    TRACE();
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

    TRACE();

    buf = X509_to_buf(TrustedCert, &len);
    dprint_data(buf, len);
    free(buf);
    dprint_data(P7Data, P7Length);
    dprint_data(InData, DataLength);


    if (EVP_add_digest(EVP_sha256()) == 0) {
        return false;
    }

    TRACE();
    Status = WrapPkcs7Data(P7Data, P7Length, &Wrapped, &SignedData,
                           &SignedDataSize);
    if (!Status) {
        DDEBUG("Status=0x%02x\n", Status);
        return Status;
    }

    Status = false;

    //
    // Retrieve PKCS#7 Data (DER encoding)
    //
    if (SignedDataSize > INT_MAX) {
        TRACE();
        goto _Exit;
    }

    Temp = SignedData;
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
    if (Pkcs7 == NULL) {
        TRACE();
        goto _Exit;
    }

    //
    // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
    //
    if (!PKCS7_type_is_signed(Pkcs7)) {
        TRACE();
        goto _Exit;
    }

    //
    // Setup X509 Store for trusted certificate
    //
    CertStore = X509_STORE_new();
    if (CertStore == NULL) {
        TRACE();
        goto _Exit;
    }

#ifndef X509_V_FLAG_NO_CHECK_TIME
    CertStore->verify_cb = X509_verify_cb;
#endif

    if (!(X509_STORE_add_cert(CertStore, TrustedCert))) {
        TRACE();
        goto _Exit;
    }

    //
    // For generic PKCS#7 handling, InData may be NULL if the content is present
    // in PKCS#7 structure. So ignore NULL checking here.
    //
    DataBio = BIO_new(BIO_s_mem());
    if (DataBio == NULL) {
        TRACE();
        goto _Exit;
    }

    if (BIO_write(DataBio, InData, (int)DataLength) <= 0) {
        TRACE();
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

    if (!Wrapped) {
        OPENSSL_free(SignedData);
    }

    TRACE();
    return Status;
}

/**
  Extracts the attached content from a PKCS#7 signed data if existed. The input signed
  data could be wrapped in a ContentInfo structure.

  If P7Data, Content, or ContentSize is NULL, then return false. If P7Length overflow,
  then return false. If the P7Data is not correctly formatted, then return false.

  Caution: This function may receive untrusted input. So this function will do
           basic check for PKCS#7 data structure.

  @param[in]   P7Data       Pointer to the PKCS#7 signed data to process.
  @param[in]   P7Length     Length of the PKCS#7 signed data in bytes.
  @param[out]  Content      Pointer to the extracted content from the PKCS#7 signedData.
                            It's caller's responsibility to free the buffer with FreePool().
  @param[out]  ContentSize  The size of the extracted content in bytes.

  @retval     true          The P7Data was correctly formatted for processing.
  @retval     false         The P7Data was not correctly formatted for processing.

**/
bool Pkcs7GetAttachedContent(const uint8_t *P7Data, uint64_t P7Length,
                             void **Content, uint64_t *ContentSize)
{
    bool Status;
    PKCS7 *Pkcs7;
    uint8_t *SignedData;
    uint64_t SignedDataSize;
    bool Wrapped;
    const uint8_t *Temp;
    ASN1_OCTET_STRING *OctStr;

    //
    // Check input parameter.
    //
    if ((P7Data == NULL) || (P7Length > INT_MAX) || (Content == NULL) ||
        (ContentSize == NULL)) {
        return false;
    }

    *Content = NULL;
    Pkcs7 = NULL;
    SignedData = NULL;
    OctStr = NULL;

    Status = WrapPkcs7Data(P7Data, P7Length, &Wrapped, &SignedData,
                           &SignedDataSize);
    if (!Status || (SignedDataSize > INT_MAX)) {
        goto _Exit;
    }

    Status = false;

    //
    // Decoding PKCS#7 SignedData
    //
    Temp = SignedData;
    Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
    if (Pkcs7 == NULL) {
        goto _Exit;
    }

    //
    // The type of Pkcs7 must be signedData
    //
    if (!PKCS7_type_is_signed(Pkcs7)) {
        goto _Exit;
    }

    //
    // Check for detached or attached content
    //
    if (PKCS7_get_detached(Pkcs7)) {
        //
        // No Content supplied for PKCS7 detached signedData
        //
        *Content = NULL;
        *ContentSize = 0;
    } else {
        //
        // Retrieve the attached content in PKCS7 signedData
        //
        OctStr = Pkcs7->d.sign->contents->d.data;
        if ((OctStr->length > 0) && (OctStr->data != NULL)) {
            *ContentSize = OctStr->length;
            *Content = malloc(*ContentSize);
            if (*Content == NULL) {
                *ContentSize = 0;
                goto _Exit;
            }
            memcpy(*Content, OctStr->data, *ContentSize);
        }
    }
    Status = true;

_Exit:
    //
    // Release Resources
    //
    PKCS7_free(Pkcs7);

    if (!Wrapped) {
        OPENSSL_free(SignedData);
    }

    return Status;
}
