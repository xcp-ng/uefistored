#include <stdbool.h>

#include "uefi/types.h"
#include "uefi/utils.h"
#include "uefi/guids.h"
#include "common.h"

bool is_secure_boot_variable(UTF16 *name, size_t namesz, EFI_GUID *guid)
{
    if (!name || !guid)
        return false;

    if (compare_guid(guid, &gEfiGlobalVariableGuid)) {
        return ((namesz == sizeof_wchar(L"PK") && memcmp(name, L"PK", namesz) == 0) ||
                (namesz == sizeof_wchar(L"KEK") && memcmp(name, L"KEK", namesz) == 0));
    }

    if (compare_guid(guid, &gEfiImageSecurityDatabaseGuid)) {
        return ((namesz == sizeof_wchar(L"db") && memcmp(name, L"db", namesz) == 0) ||
                (namesz == sizeof_wchar(L"dbx") && memcmp(name, L"dbx", namesz) == 0) ||
                (namesz == sizeof_wchar(L"dbt") && memcmp(name, L"dbt", namesz) == 0));
    }

    return false;
}
