#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>

#include "serializer.h"
#include "XenVariable.h"

#define DEBUG 1

#if DEBUG
#include <stdio.h>
#define DPRINTF(...)                 \
    do {                             \
        printf(__VA_ARGS__);     \
    } while ( 0 )
#else
#define DPRINTF(...)  do { } while ( 0 )
#endif


#define exec_command(...) do { } while ( 0 )
#define AcquireSpinLock(...) do { } while( 0 )
#define ReleaseSpinLock(...) do { } while( 0 )
#define UNUSED(var) ((void)var)

static void *comm_buf;

void mock_xenvariable_set_buffer(void *p)
{
    comm_buf = p;
}

static size_t StrLen(char16_t *str)
{
    size_t ret = 0;
    uint16_t *p = (uint16_t*)str;

    while (*(p++))
        ret++;

    return ret;
}

#define StrSize(str) StrLen(str)

static inline void *AllocatePages(size_t pages)
{
    return malloc(pages * PAGE_SIZE);
}

#if 0
static
EFI_STATUS
XenNotifySecureBootFailure (
  void
  )
{
  uint8_t *ptr;
  EFI_STATUS status;
  void *comm_buf;

  comm_buf = AllocatePages(SHMEM_PAGES);
  if (!comm_buf)
    return EFI_OUT_OF_RESOURCES;

  ptr = comm_buf;
  serialize_uint32(&ptr, 1); /* version */
  serialize_uint32(&ptr, COMMAND_NOTIFY_SB_FAILURE);

  exec_command(comm_buf);

  ptr = comm_buf;
  status = unserialize_result(&ptr);

  free(comm_buf);

  return status;
}
#endif

static inline int EfiAtRuntime(void)
{
    return 1;
}

EFI_STATUS
XenGetVariableLocked (
    char16_t            *VariableName,
    EFI_GUID          *VendorGuid,
    uint32_t            *Attributes,
    uint64_t             *DataSize,
    void              *Data
    )
{
  uint8_t *ptr;
  EFI_STATUS status;
  uint32_t attr;

  if (!VariableName || !VendorGuid || !DataSize)
      return EFI_INVALID_PARAMETER;

  ptr = comm_buf;
  serialize_uint32(&ptr, 1); /* version */
  serialize_command(&ptr, COMMAND_GET_VARIABLE);
  serialize_name(&ptr, VariableName);
  serialize_guid(&ptr, VendorGuid);
  serialize_uintn(&ptr, *DataSize);
  serialize_boolean(&ptr, EfiAtRuntime());

  exec_command(comm_buf);
  ptr = comm_buf;

#if 0
  status = unserialize_result(&ptr);
  switch (status) {
  case EFI_SUCCESS:
    if (!Data)
        return EFI_INVALID_PARAMETER;
    attr = unserialize_uint32(&ptr);
    if (Attributes)
        *Attributes = attr;
    unserialize_data(&ptr, Data, DataSize);
    break;
  case EFI_BUFFER_TOO_SMALL:
    *DataSize = unserialize_uintn(&ptr);
    break;
  default:
    break;
  }

  return status;
#endif
    return 0;
}
  
EFI_STATUS
XenGetVariable (
        char16_t            *VariableName,
        EFI_GUID          *VendorGuid,
       uint32_t            *Attributes,
     uint64_t             *DataSize,
       void              *Data
  )
{
  EFI_STATUS status;

  AcquireSpinLock(&var_lock);

  status = XenGetVariableLocked(VariableName, VendorGuid, Attributes,
                                DataSize, Data);

  ReleaseSpinLock(&var_lock);

  return status;
}

EFI_STATUS
XenGetNextVariableNameLocked (
     uint64_t             *VariableNameSize,
     char16_t            *VariableName,
     EFI_GUID          *VendorGuid
  )
{
  uint8_t *ptr;
  EFI_STATUS status;
  UNUSED(status);

  if (!VariableNameSize || !VariableName || !VendorGuid)
      return EFI_INVALID_PARAMETER;

  if (StrSize(VariableName) > *VariableNameSize)
      return EFI_INVALID_PARAMETER;

  ptr = comm_buf;
  serialize_uint32(&ptr, 1); /* version */
  serialize_command(&ptr, COMMAND_GET_NEXT_VARIABLE);
  serialize_uintn(&ptr, *VariableNameSize);
  serialize_name(&ptr, VariableName);
  serialize_guid(&ptr, VendorGuid);
  serialize_boolean(&ptr, EfiAtRuntime());

#if 0
  exec_command(comm_buf);

  ptr = comm_buf;
  status = unserialize_result(&ptr);
  switch (status) {
  case EFI_SUCCESS:
    unserialize_data(&ptr, VariableName, VariableNameSize);
    VariableName[*VariableNameSize / 2] = '\0';
    *VariableNameSize = sizeof(*VariableName);
    unserialize_guid(&ptr, VendorGuid);
    break;
  case EFI_BUFFER_TOO_SMALL:
    *VariableNameSize = unserialize_uintn(&ptr);
    break;
  default:
    break;
  }
  return status;
#else
  return 0;
#endif
}

EFI_STATUS
XenGetNextVariableName (
     uint64_t             *VariableNameSize,
     char16_t            *VariableName,
     EFI_GUID          *VendorGuid
  )
{
  EFI_STATUS status;

  AcquireSpinLock(&var_lock);

  status = XenGetNextVariableNameLocked(VariableNameSize, VariableName,
                                        VendorGuid);

  ReleaseSpinLock(&var_lock);

  return status;
}

EFI_STATUS
XenSetVariableLocked (
   char16_t                  *VariableName,
   EFI_GUID                *VendorGuid,
   uint32_t                  Attributes,
   uint64_t                   DataSize,
   void                    *Data
  )
{
  uint8_t *ptr;
  ptr = comm_buf;
  serialize_uint32(&ptr, 1); /* version */
  serialize_command(&ptr, COMMAND_SET_VARIABLE);
  serialize_name(&ptr, VariableName);
  serialize_guid(&ptr, VendorGuid);
  serialize_data(&ptr, Data, DataSize);
  serialize_uint32(&ptr, Attributes);
  serialize_boolean(&ptr, EfiAtRuntime());

#if 0
  ptr = comm_buf;
  return unserialize_result(&ptr);
#else
  return 0;
#endif
}

EFI_STATUS
XenSetVariable (
   char16_t                  *VariableName,
   EFI_GUID                *VendorGuid,
   uint32_t                  Attributes,
   uint64_t                   DataSize,
   void                    *Data
)
{
  EFI_STATUS status;

  AcquireSpinLock(&var_lock);

  status = XenSetVariableLocked(VariableName, VendorGuid, Attributes,
                                DataSize, Data);

  ReleaseSpinLock(&var_lock);

  return status;
}

EFI_STATUS
XenQueryVariableInfoLocked (
   uint32_t                 Attributes,
   uint64_t                 *MaximumVariableStorageSize,
   uint64_t                 *RemainingVariableStorageSize,
   uint64_t                 *MaximumVariableSize
  )
{
  uint8_t *ptr;
  EFI_STATUS status;

  UNUSED(status);

  ptr = comm_buf;
  serialize_uint32(&ptr, 1); /* version */
  serialize_command(&ptr, COMMAND_QUERY_VARIABLE_INFO);
  serialize_uint32(&ptr, Attributes);

#if 0
  exec_command(comm_buf);

  ptr = comm_buf;
  status = unserialize_result(&ptr);
  switch (status) {
  case EFI_SUCCESS:
    *MaximumVariableStorageSize = unserialize_uint64(&ptr);
    *RemainingVariableStorageSize = unserialize_uint64(&ptr);
    *MaximumVariableSize = unserialize_uint64(&ptr);
    break;
  default:
    break;
  }
  return status;
#else
  return 0;
#endif
}

EFI_STATUS
XenQueryVariableInfo (
   uint32_t                 Attributes,
   uint64_t                 *MaximumVariableStorageSize,
   uint64_t                 *RemainingVariableStorageSize,
   uint64_t                 *MaximumVariableSize
  )
{
  EFI_STATUS status;
  status = XenQueryVariableInfoLocked(Attributes, MaximumVariableStorageSize,
                                      RemainingVariableStorageSize,
                                      MaximumVariableSize);
  return status;
}
