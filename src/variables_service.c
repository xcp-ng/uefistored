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

/**
 * Returns true if variable is read-only, otherwise false.
 */
static bool is_ro(UTF16 *variable)
{
    if (!variable)
        return false;

    return strcmp16(variable, SECURE_BOOT_NAME) == 0;
}

EFI_STATUS set_variable(UTF16 *name, EFI_GUID *guid, uint32_t attrs,
                        size_t datasz, void *data)
{
    EFI_STATUS status;

    if (!name || !guid || !data)
        return -1;

    if (name[0] == 0 ||
            ((attrs & EFI_VARIABLE_RUNTIME_ACCESS) &&
             !(attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS)))
        return EFI_INVALID_PARAMETER;

    if (is_ro(name))
        return EFI_WRITE_PROTECTED;

    status = evaluate_attrs(attrs);

    if (status != EFI_SUCCESS)
        return status;

    if (attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
        status = AuthVariableLibProcessVariable(name, guid, data, datasz, attrs);
    } else {
        status = storage_set(name, guid, data, datasz, attrs);
    }

#if DEBUG
    DPRINTF("%s:%d: ", __func__, __LINE__);
    dprint_name(name, strsize16(name));
    DPRINTF(", attrs=0x%02x", attrs);
    DPRINTF(", guid=0x%02x", guid->Data1);

    uint8_t *p;
    size_t i;

    p = data;

    DPRINTF(", data (%lu)=", datasz);
    for (i=0; i<datasz; i++) {
        DPRINTF("0x%02x, ", p[i]);
    }
    DPRINTF(", status=%s", efi_status_str(status));
    DPRINTF("\n");
#endif

    return status;
}
