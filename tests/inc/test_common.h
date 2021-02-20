#ifndef __H_COMMON_
#define __H_COMMON_

#include "uefi/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define DEFINE_AUTH_FILE(fname, _name, _guid, _attrs)                          \
    {                                                                          \
        .path = fname,                                                         \
        .var = {                                                               \
            .name = _name,                                                     \
            .namesz = sizeof_wchar(_name),                                           \
            .guid = _guid,                                                     \
            .attrs = _attrs,                                                   \
        },                                                                     \
    }

#define AT_ATTRS                                                               \
    EFI_VARIABLE_NON_VOLATILE |                                                \
            EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |               \
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS

#define _DEFAULT_ATTRS                                               \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |   \
     EFI_VARIABLE_RUNTIME_ACCESS)

#define DEFAULT_GUID { .Data1 = 0xc0defeed }
#define DEFAULT_ATTR                                                 \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |   \
     EFI_VARIABLE_RUNTIME_ACCESS)

EFI_STATUS testutil_query_variable_info(uint32_t Attributes,
                                   uint64_t *MaximumVariableStorageSize,
                                   uint64_t *RemainingVariableStorageSize,
                                   uint64_t *MaximumVariableSize);

EFI_STATUS testutil_set_variable(wchar_t *name, size_t namesz, EFI_GUID *guid,
                                 uint32_t attr, size_t datasize, void *data);

EFI_STATUS testutil_get_variable(wchar_t *variable, size_t namesz, EFI_GUID *guid,
                                 uint32_t *attrs, size_t *size,
                                 void *data);

int file_to_buf(const char *fpath, uint8_t *bytes, size_t n);

#endif //  __H_COMMON_
