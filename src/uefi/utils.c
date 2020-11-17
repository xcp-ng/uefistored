#include <stdbool.h>

#include "uefi/types.h"
#include "uefi/utils.h"
#include "uefi/guids.h"
#include "common.h"

bool is_secure_boot_variable(UTF16 *name, EFI_GUID *guid)
{
    if (!name || !guid)
        return false;

    if (compare_guid(guid, &gEfiGlobalVariableGuid)) {
        return !strcmp16(name, L"PK") || !strcmp16(name, L"KEK");
    }

    if (compare_guid(guid, &gEfiImageSecurityDatabaseGuid)) {
        return !strcmp16(name, L"db") || !strcmp16(name, L"dbx") || !strcmp16(name, L"dbt");
    }

    return false;
}
