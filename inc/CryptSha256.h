#ifndef __H_CRYPT_SHA256_
#define __H_CRYPT_SHA256_

#include "uefitypes.h"

UINTN
Sha256GetContextSize (
  VOID
  );

BOOLEAN
Sha256Init (
  OUT  VOID  *Sha256Context
  );

BOOLEAN
Sha256Duplicate (
  IN   CONST VOID  *Sha256Context,
  OUT  VOID        *NewSha256Context
  );

BOOLEAN
Sha256Update (
  IN OUT  VOID        *Sha256Context,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  );

BOOLEAN
Sha256Final (
  IN OUT  VOID   *Sha256Context,
  OUT     UINT8  *HashValue
  );

BOOLEAN
Sha256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

#endif // __H_CRYPT_SHA256_
