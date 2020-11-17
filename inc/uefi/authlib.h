#ifndef __H_AUTHLIB_UEFI_
#define __H_AUTHLIB_UEFI_

#include "uefi/types.h"

struct auth_data {
    char path[PATH_MAX];
    variable_t var;
};

EFI_STATUS auth_lib_process_variable (
    UTF16 *VariableName,
    EFI_GUID *VendorGuid,
    void *Data,
    uint64_t DataSize,
    uint32_t Attributes
);

EFI_STATUS auth_lib_initialize(struct auth_data *auths, size_t n);
int auth_lib_load(struct auth_data *auths, size_t n);

#endif // __H_AUTHLIB_UEFI_
