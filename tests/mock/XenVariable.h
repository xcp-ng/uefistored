#ifndef __H_XENVARIABLE_
#define __H_XENVARIABLE_

#include <stdint.h>
#include <stdlib.h>
#include <uchar.h>

#include "serializer.h"
#include "uefi/types.h"

#define PORT_ADDRESS 0x0100
#define SHMEM_PAGES  16

#define PAGE_SIZE (4<<10)


static inline void *AllocateRuntimePages(size_t pages)
{
    return malloc(pages * PAGE_SIZE);
}

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

void mock_xen_variable_server_set_buffer(void *p);

#endif // __H_XENVARIABLE_
