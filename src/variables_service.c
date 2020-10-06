#include "common.h"
#include "log.h"
#include "storage.h"
#include "uefi/authlib.h"
#include "uefi/types.h"
#include "uefi/guids.h"
#include "varnames.h"
#include "variable.h"

#define DEBUG_VARIABLES_SERVICE 1

bool efi_at_runtime = false;

void set_efi_runtime(bool runtime)
{
    efi_at_runtime = runtime;
}

EFI_STATUS evaluate_attrs(uint32_t attrs)
{
    /* No support for hardware error record */
    if (attrs & EFI_VARIABLE_HARDWARE_ERROR_RECORD)
        return EFI_UNSUPPORTED;
    /* If RT is set, BS must also be set */
    else if ((attrs & RT_BS_ATTRS) == EFI_VARIABLE_RUNTIME_ACCESS)
        return EFI_INVALID_PARAMETER;
    /* Not both authentication bits may be set */
    else if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) && \
             (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS))
        return EFI_SECURITY_VIOLATION;
    /* We do not support EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS */
    else if (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
        return EFI_SECURITY_VIOLATION;
    else if (attrs & EFI_VARIABLE_APPEND_WRITE)
        DDEBUG("attrs & EFI_VARIABLE_APPEND_WRITE");

    return EFI_SUCCESS;
}
