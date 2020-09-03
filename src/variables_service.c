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
        return EFI_UNSUPPORTED;
    /* We do not support EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS */
    else if (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
        return EFI_UNSUPPORTED;

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

EFI_STATUS
get_variable(UTF16 *variable, EFI_GUID *guid, uint32_t *attrs, size_t *size,
             void *data)
{
    size_t buffer_size;
    EFI_STATUS status;

    if (!variable || !guid || !attrs || !size || !data)
        return EFI_INVALID_PARAMETER;

    buffer_size = *size;

#if 0
    if (strcmp16(variable, L"SecureBoot") == 0
            && memcmp(guid, &gEfiGlobalVariableGuid, sizeof(EFI_GUID)) == 0) {

        if (*size < sizeof(uint8_t)) {
            status = EFI_BUFFER_TOO_SMALL;
        } else {
            uint8_t val = 0;
            memcpy(data, &val, sizeof(val));
        }

        *size = sizeof(uint8_t);
        *attrs = EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_NON_VOLATILE;
        status = EFI_SUCCESS;
    } else if (strcmp16(variable, L"SetupMode") == 0
            && memcmp(guid, &gEfiGlobalVariableGuid, sizeof(EFI_GUID)) == 0) {
        if (*size < sizeof(uint8_t)) {
            status = EFI_BUFFER_TOO_SMALL;
        } else {
            uint8_t val = 1;
            memcpy(data, &val, sizeof(val));
        }

        *size = sizeof(uint8_t);
        *attrs = EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_NON_VOLATILE;
        status = EFI_SUCCESS;
    } else {
        status = storage_get(variable, guid, attrs, data, size);
    }
#endif

    status = storage_get(variable, guid, attrs, data, size);

#if DEBUG_VARIABLES_SERVICE
    DPRINTF("%s:%d: ", __func__, __LINE__);
    dprint_name(variable, strsize16(variable));
    DPRINTF(", guid=0x%02x", guid->Data1);
    if (!status)
        DPRINTF(", attrs=0x%02x, ", *attrs);
    DPRINTF(", status=%s (0x%02lx), size=%lu, buffer_size=%lu",
            efi_status_str(status), status, *size, buffer_size);


    if (!status) {
        uint8_t *p;
        size_t i;

        p = data;

        DPRINTF(", data (%lu)=", *size);
        for (i=0; i<*size; i++) {
            DPRINTF("0x%02x, ", p[i]);
        }
    }
    DPRINTF("\n");
#endif

    return status;
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
        return EFI_UNSUPPORTED;

    if (attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
        return AuthVariableLibProcessVariable(name, guid, data, datasz, attrs);
    }

    status = storage_set(name, guid, data, datasz, attrs);

#if DEBUG_VARIABLES_SERVICE
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

EFI_STATUS query_variable_info(uint32_t attrs, uint64_t *max_variable_storage,
                               uint64_t *remaining_variable_storage,
                               uint64_t *max_variable_size)
{
    if (attrs == 0 ||
            ((attrs & EFI_VARIABLE_RUNTIME_ACCESS) &&
             !(attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS)))
        return EFI_INVALID_PARAMETER;

    DEBUG("attrs=0x%02x\n", attrs);

    *max_variable_storage = MAX_STORAGE_SIZE;
    *max_variable_size = MAX_VARIABLE_SIZE;
    *remaining_variable_storage = MAX_STORAGE_SIZE - storage_used();

    return EFI_SUCCESS;
}
