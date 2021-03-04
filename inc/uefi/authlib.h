#ifndef __H_AUTHLIB_UEFI_
#define __H_AUTHLIB_UEFI_

#include <limits.h>
#include "variable.h"
#include "uefi/types.h"

struct auth_data {
    char path[PATH_MAX];
    variable_t var;
};

EFI_STATUS auth_lib_process_variable (
    UTF16 *name,
    size_t namesz,
    EFI_GUID *guid,
    void *data,
    uint64_t datasz,
    uint32_t attrs
);

EFI_STATUS auth_lib_initialize(struct auth_data *auths, size_t n);
void auth_lib_deinit(struct auth_data *auths, size_t n);
void auth_lib_load(struct auth_data *auths, size_t n);

#endif // __H_AUTHLIB_UEFI_
