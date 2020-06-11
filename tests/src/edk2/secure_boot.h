#ifndef __H_SECURE_BOOT_
#define __H_SECURE_BOOT_

#include "uefitypes.h"

EFI_STATUS
EnrollPlatformKey (
   EFI_GUID* guid,
   EFI_GUID *CertTypeGuid,
   char*   FileName
  );

#endif // __H_SECURE_BOOT_
