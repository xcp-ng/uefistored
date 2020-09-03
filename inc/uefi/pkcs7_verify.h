#ifndef __H_PKCS7_VERIFY_
#define __H_PKCS7_VERIFY_

bool Pkcs7GetSigners (
  const uint8_t  *P7Data,
  uint64_t        P7Length,
 uint8_t        **CertStack,
 uint64_t        *StackLength,
 uint8_t        **TrustedCert,
 uint64_t        *CertLength
  );

bool Pkcs7Verify (
  const uint8_t  *P7Data,
  uint64_t        P7Length,
  const uint8_t  *TrustedCert,
  uint64_t        CertLength,
  const uint8_t  *InData,
  uint64_t        DataLength
  );

void Pkcs7FreeSigners (
  uint8_t        *Certs
  );

#endif // __H_PKCS7_VERIFY_
