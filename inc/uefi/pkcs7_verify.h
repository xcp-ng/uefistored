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

uint8_t *X509_to_buf(X509 *cert, int *len);

static inline X509* X509_from_buf(const uint8_t *buf, long len)
{
    const uint8_t *ptr = buf;

    return d2i_X509(NULL, &ptr, len);
}

EFI_STATUS pkcs7_get_signers(PKCS7 *pkcs7, STACK_OF(X509) **certs);
PKCS7 *pkcs7_from_auth(EFI_VARIABLE_AUTHENTICATION_2 *auth);
X509 *pkcs7_get_top_cert(PKCS7 *pkcs7);
uint8_t *pkcs7_get_top_cert_der(PKCS7 *pkcs7, int *top_cert_der_size);
uint8_t *wrap_with_content_info(const uint8_t *data, uint32_t size,  uint32_t *new_size);
bool is_content_info(const uint8_t *data, size_t data_size);
bool pkcs7_verify(PKCS7 *pkcs7, X509 *TrustedCert,
                  const uint8_t *new_data, uint64_t new_data_size);

#endif // __H_PKCS7_VERIFY_
