#ifndef __H_UTILS_UEFI_
#define __H_UTILS_UEFI_

#include "uefi/types.h"

static inline bool CompareGuid(EFI_GUID *a, EFI_GUID *b)
{
    return memcmp(a, b, sizeof(EFI_GUID)) == 0;
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
