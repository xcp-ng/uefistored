#ifndef __H_X509__
#define __H_X509__

#include "uefi/types.h"

bool RsaGetPublicKeyFromX509 (
  const uint8_t  *Cert,
  uint64_t        CertSize,
  void         **RsaContext
  );

RETURN_STATUS X509GetCommonName (
      const uint8_t  *Cert,
      uint64_t        CertSize,
      char        *CommonName,
       uint64_t        *CommonNameSize
  );

bool X509GetTBSCert (
  const uint8_t  *Cert,
  uint64_t        CertSize,
 uint8_t        **TBSCert,
 uint64_t        *TBSCertSize
  );

#endif // __H_X509__
