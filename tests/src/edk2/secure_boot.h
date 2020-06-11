#ifndef __H_SECURE_BOOT_
#define __H_SECURE_BOOT_

#include "uefitypes.h"

EFI_STATUS
EnrollPlatformKey (
   char*   FileName
  );

#endif // __H_SECURE_BOOT_
