#ifndef __H_XENVARIABLE_
#define __H_XENVARIABLE_

#include <stdint.h>
#include <stdlib.h>
#include <uchar.h>

#include "xenvar.h"

#define PORT_ADDRESS 0x0100
#define SHMEM_PAGES  16

#define PAGE_SIZE (4<<10)


static inline void *AllocateRuntimePages(size_t pages)
{
    return malloc(pages * PAGE_SIZE);
}

typedef struct {
    uint8_t guid[16];
} EFI_GUID;

typedef enum {
    EFI_SUCCESS = 0,
    EFI_INVALID_PARAMETER = 2,
    EFI_BUFFER_TOO_SMALL = 5,
    EFI_OUT_OF_RESOURCES = 9,
} efi_status_t;

typedef uint64_t EFI_STATUS;

EFI_STATUS
XenGetVariable (
        char16_t            *VariableName,
        EFI_GUID          *VendorGuid,
       uint32_t            *Attributes,
     uint64_t             *DataSize,
       void              *Data
  );

EFI_STATUS
XenSetVariable (
   char16_t                  *VariableName,
   EFI_GUID                *VendorGuid,
   uint32_t                  Attributes,
   uint64_t                   DataSize,
   void                    *Data
);

EFI_STATUS
XenQueryVariableInfo (
   uint32_t                 Attributes,
   uint64_t                 *MaximumVariableStorageSize,
   uint64_t                 *RemainingVariableStorageSize,
   uint64_t                 *MaximumVariableSize
  );

EFI_STATUS
XenGetNextVariableName (
     uint64_t             *VariableNameSize,
     char16_t            *VariableName,
     EFI_GUID          *VendorGuid
  );

void mock_xenvariable_set_buffer(void *p);

#endif // __H_XENVARIABLE_
