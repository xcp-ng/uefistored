#ifndef __H_UTILS_UEFI_
#define __H_UTILS_UEFI_

#include "uefi/types.h"
#include "uefi/guids.h"

extern EFI_GUID gEfiGlobalVariableGuid;
extern EFI_GUID gEfiImageSecurityDatabaseGuid;

bool is_secure_boot_variable(UTF16 *name, size_t namesz, EFI_GUID *guid);

/**
 * Compare two guids.
 *
 * @parm guid1 A guid to compare
 * @parm guid2 A guid to compare
 *
 * @return true if two guids are equal, otherwise false.
 */
static inline bool compare_guid(EFI_GUID *guid1, EFI_GUID *guid2)
{
    return memcmp(guid1, guid2, sizeof(EFI_GUID)) == 0;
}

static inline void WriteUnaligned32(uint32_t *dest, uint32_t val)
{
    memcpy(dest, &val, sizeof(*dest));
}

static inline uint32_t ReadUnaligned32(uint32_t *src)
{
    uint32_t val;

    memcpy(&val, src, sizeof(val));

    return val;
}

static inline bool UserPhysicalPresent(void)
{
    /* Always True for OVMF */
    return true;
}

#endif // __H_UTILS_UEFI_
