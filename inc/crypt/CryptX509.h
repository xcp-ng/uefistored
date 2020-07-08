#ifndef __H_CRYPTX509_
#define __H_CRYPTX509_

#include "uefitypes.h"

BOOLEAN
X509ConstructCertificate (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  UINT8        **SingleX509Cert
  );

BOOLEAN
X509ConstructCertificateStack (
  IN OUT  UINT8  **X509Stack,
  ...
  );

VOID
X509Free (
  IN  VOID  *X509Cert
  );

VOID
X509StackFree (
  IN  VOID  *X509Stack
  );

BOOLEAN
X509GetSubjectName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     UINT8        *CertSubject,
  IN OUT  UINTN        *SubjectSize
  );

RETURN_STATUS
X509GetCommonName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     CHAR8        *CommonName,
  IN OUT  UINTN        *CommonNameSize
  );

BOOLEAN
RsaGetPublicKeyFromX509 (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **RsaContext
  );

BOOLEAN
X509VerifyCert (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *CACert,
  IN  UINTN        CACertSize
  );

BOOLEAN
X509GetTBSCert (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  OUT UINT8        **TBSCert,
  OUT UINTN        *TBSCertSize
  );

#endif // __H_CRYPTX509_
