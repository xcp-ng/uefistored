#ifndef __H_PKCS7_VERIFY_
#define __H_PKCS7_VERIFY_

#include "uefi/image_authentication.h"
#include <openssl/x509.h>

bool Pkcs7GetSigners (
  const uint8_t   *P7Data,
  uint64_t         P7Length,
  STACK_OF(X509) **CertStack,
  uint64_t        *StackLength
  );

bool Pkcs7Verify (
  const uint8_t  *P7Data,
  uint64_t        P7Length,
  const X509  *TrustedCert,
  const uint8_t  *InData,
  uint64_t        DataLength
  );

void Pkcs7FreeSigners (
  X509        *Certs
  );

bool WrapPkcs7Data(const uint8_t *P7Data, uint64_t P7Length, bool *WrapFlag,
                   uint8_t **WrapData, uint64_t *WrapDataSize);

uint8_t *X509_to_buf(X509 *cert, int *len);

static inline X509* X509_from_buf(const uint8_t *buf, long len)
{
    const uint8_t *ptr = buf;

    return d2i_X509(NULL, &ptr, len);
}

EFI_STATUS pkcs7_get_signers(const uint8_t *p7data, uint64_t p7_len,
                                    PKCS7 **pkcs7, STACK_OF(X509) **certs);

PKCS7 *pkcs7_from_auth(EFI_VARIABLE_AUTHENTICATION_2 *auth);
uint8_t *pkcs7_get_top_cert_der(PKCS7 *pkcs7, int *top_cert_der_size);

#endif // __H_PKCS7_VERIFY_
