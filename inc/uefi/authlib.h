#ifndef __H_AUTHLIB_UEFI_
#define __H_AUTHLIB_UEFI_

#include "uefi/types.h"

EFI_STATUS auth_lib_process_variable (
    UTF16 *VariableName,
    EFI_GUID *VendorGuid,
    void *Data,
    uint64_t DataSize,
    uint32_t Attributes
);

EFI_STATUS auth_lib_initialize(void);
int auth_lib_load(const char *pk_auth_file);

#endif // __H_AUTHLIB_UEFI_
