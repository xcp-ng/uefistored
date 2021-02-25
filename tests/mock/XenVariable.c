#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>

#include "serializer.h"
#include "XenVariable.h"

#define exec_command(...) do { } while (0)
#define AcquireSpinLock(...) do { } while (0)
#define ReleaseSpinLock(...) do { } while (0)

static void *comm_buf;

void mock_xen_variable_server_set_buffer(void *p)
{
    comm_buf = p;
}

static size_t StrLen(char16_t *str)
{
    size_t ret = 0;
    uint16_t *p = (uint16_t *)str;

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
XenGetVariableLocked(char16_t *VariableName, EFI_GUID *VendorGuid,
                     uint32_t *Attributes, uint64_t *DataSize, void *Data)
{
    uint8_t *ptr;

    if (!VariableName || !VendorGuid || !DataSize)
        return EFI_INVALID_PARAMETER;

    ptr = comm_buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_command(&ptr, COMMAND_GET_VARIABLE);
   
    serialize_name(&ptr, VariableName, strsize16(VariableName));
    serialize_guid(&ptr, VendorGuid);
    serialize_uintn(&ptr, *DataSize);
    serialize_boolean(&ptr, EfiAtRuntime());

    exec_command(comm_buf);
    ptr = comm_buf;

    return 0;
}

EFI_STATUS
XenGetVariable(char16_t *VariableName, EFI_GUID *VendorGuid,
               uint32_t *Attributes, uint64_t *DataSize, void *Data)
{
    EFI_STATUS status;

    AcquireSpinLock(&var_lock);

    status = XenGetVariableLocked(VariableName, VendorGuid, Attributes,
                                  DataSize, Data);

    ReleaseSpinLock(&var_lock);

    return status;
}

EFI_STATUS
XenGetNextVariableNameLocked(uint64_t *VariableNameSize, char16_t *VariableName,
                             EFI_GUID *VendorGuid)
{
    uint8_t *ptr;

    if (!VariableNameSize || !VariableName || !VendorGuid)
        return EFI_INVALID_PARAMETER;

    if (StrSize(VariableName) > *VariableNameSize)
        return EFI_INVALID_PARAMETER;

    ptr = comm_buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_command(&ptr, COMMAND_GET_NEXT_VARIABLE);
    serialize_uintn(&ptr, *VariableNameSize);
    serialize_name(&ptr, VariableName, strsize16(VariableName));
    serialize_guid(&ptr, VendorGuid);
    serialize_boolean(&ptr, EfiAtRuntime());

    return 0;
}

EFI_STATUS
XenGetNextVariableName(uint64_t *VariableNameSize, char16_t *VariableName,
                       EFI_GUID *VendorGuid)
{
    EFI_STATUS status;

    AcquireSpinLock(&var_lock);

    status = XenGetNextVariableNameLocked(VariableNameSize, VariableName,
                                          VendorGuid);

    ReleaseSpinLock(&var_lock);

    return status;
}

EFI_STATUS
XenSetVariableLocked(char16_t *VariableName, EFI_GUID *VendorGuid,
                     uint32_t Attributes, uint64_t DataSize, void *Data)
{
    uint8_t *ptr;
    ptr = comm_buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_command(&ptr, COMMAND_SET_VARIABLE);
    serialize_name(&ptr, VariableName, strsize16(VariableName));
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
XenSetVariable(char16_t *VariableName, EFI_GUID *VendorGuid,
               uint32_t Attributes, uint64_t DataSize, void *Data)
{
    EFI_STATUS status;

    AcquireSpinLock(&var_lock);

    status = XenSetVariableLocked(VariableName, VendorGuid, Attributes,
                                  DataSize, Data);

    ReleaseSpinLock(&var_lock);

    return status;
}

EFI_STATUS
XenQueryVariableInfoLocked(uint32_t Attributes,
                           uint64_t *MaximumVariableStorageSize,
                           uint64_t *RemainingVariableStorageSize,
                           uint64_t *MaximumVariableSize)
{
    uint8_t *ptr;

    ptr = comm_buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_command(&ptr, COMMAND_QUERY_VARIABLE_INFO);
    serialize_uint32(&ptr, Attributes);
    return 0;
}

EFI_STATUS
XenQueryVariableInfo(uint32_t Attributes, uint64_t *MaximumVariableStorageSize,
                     uint64_t *RemainingVariableStorageSize,
                     uint64_t *MaximumVariableSize)
{
    EFI_STATUS status;
    status = XenQueryVariableInfoLocked(Attributes, MaximumVariableStorageSize,
                                        RemainingVariableStorageSize,
                                        MaximumVariableSize);
    return status;
}
