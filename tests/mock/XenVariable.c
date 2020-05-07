#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>

#include "XenVariable.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#endif

#define DPRINTF(...)                 \
    do {                             \
        if (DEBUG)                   \
            printf(__VA_ARGS__);     \
    } while ( 0 )

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

static inline void
serialize_name(uint8_t **ptr, char16_t *VariableName)
{
  uint64_t VarNameSize = StrLen(VariableName) * sizeof(*VariableName);
  memcpy (*ptr, &VarNameSize, sizeof VarNameSize);
  *ptr += sizeof VarNameSize;
  memcpy (*ptr, VariableName, VarNameSize);
  *ptr += VarNameSize;
}

static inline void
serialize_data(uint8_t **ptr, void *Data, uint64_t DataSize)
{
  memcpy (*ptr, &DataSize, sizeof DataSize);
  *ptr += sizeof DataSize;
  memcpy (*ptr, Data, DataSize);
  *ptr += DataSize;
}

static inline void
serialize_uintn(uint8_t **ptr, uint64_t var)
{
  memcpy (*ptr, &var, sizeof var);
  *ptr += sizeof var;
}

static inline void
serialize_uint32(uint8_t **ptr, uint32_t var)
{
  memcpy (*ptr, &var, sizeof var);
  *ptr += sizeof var;
}

static inline void
serialize_boolean(uint8_t **ptr, bool var)
{
  memcpy (*ptr, &var, sizeof var);
  *ptr += sizeof var;
}

static inline void
serialize_command(uint8_t **ptr, command_t cmd)
{
  serialize_uint32(ptr, (uint32_t)cmd);
}

static inline void
serialize_guid(uint8_t **ptr, EFI_GUID *Guid)
{
  memcpy (*ptr, Guid, 16);
  *ptr += 16;
}

#if 0
static inline void
unserialize_data(uint8_t **ptr, void *Data, uint64_t *DataSize)
{
  memcpy(DataSize, *ptr, sizeof(*DataSize));
  *ptr += sizeof(*DataSize);
  memcpy(Data, *ptr, *DataSize);
  *ptr += *DataSize;
}

static inline uint64_t
unserialize_uintn(uint8_t **ptr)
{
  uint64_t ret;

  memcpy(&ret, *ptr, sizeof ret);
  *ptr += sizeof ret;

  return ret;
}

static inline uint32_t
unserialize_uint32(uint8_t **ptr)
{
  uint32_t ret;

  memcpy(&ret, *ptr, sizeof ret);
  *ptr += sizeof ret;

  return ret;
}

static inline uint64_t
unserialize_uint64(uint8_t **ptr)
{
  uint64_t ret;

  memcpy(&ret, *ptr, sizeof ret);
  *ptr += sizeof ret;

  return ret;
}

static inline void
unserialize_guid(uint8_t **ptr, EFI_GUID *Guid)
{
  memcpy (Guid, *ptr, 16);
  *ptr += 16;
}

static inline EFI_STATUS
unserialize_result(uint8_t **ptr)
{
  EFI_STATUS status;

  memcpy(&status, *ptr, sizeof status);
  *((uint64_t*)ptr) = sizeof(status);

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

  UNUSED(status);
  UNUSED(attr);

  ptr = comm_buf;
  serialize_uint32(&ptr, 1); /* version */
  serialize_command(&ptr, COMMAND_GET_VARIABLE);
  serialize_name(&ptr, VariableName);
  serialize_guid(&ptr, VendorGuid);
  serialize_uintn(&ptr, *DataSize);
  serialize_boolean(&ptr, EfiAtRuntime());

#if 0
  exec_command(comm_buf_phys);
  ptr = comm_buf;
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
#else
  return 0;
#endif
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
  exec_command(comm_buf_phys);

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

  exec_command(comm_buf_phys);

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
  exec_command(comm_buf_phys);

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
