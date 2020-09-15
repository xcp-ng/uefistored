#ifndef __H_AUTHLIB_UEFI_
#define __H_AUTHLIB_UEFI_

#include "uefi/types.h"

EFI_STATUS
AuthVariableLibProcessVariable (
 UTF16         *VariableName,
 EFI_GUID       *VendorGuid,
 void           *Data,
 uint64_t          DataSize,
 uint32_t         Attributes
  );

EFI_STATUS
AuthVariableLibInitialize (void);

#endif // __H_AUTHLIB_UEFI_