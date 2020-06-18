#ifndef __H_SECURE_BOOT_
#define __H_SECURE_BOOT_

#include <stdint.h>
#include "uefitypes.h"

EFI_STATUS
EnrollPlatformKey (
   EFI_GUID* guid,
   EFI_GUID *CertTypeGuid,
   char*   FileName,
   uint8_t seconds
  );

EFI_STATUS ReadFileContent(const char *file, void **data,
                           uint64_t *datasize);

#endif // __H_SECURE_BOOT_
