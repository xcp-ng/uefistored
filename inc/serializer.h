#ifndef __H_SERIALIZER_
#define __H_SERIALIZER

#include <stdbool.h>
#include <stdint.h>
#include <uchar.h>

#include "uefitypes.h"

void serialize_name(uint8_t **ptr, char16_t *VariableName);
void serialize_data(uint8_t **ptr, void *Data, uint64_t DataSize);
void serialize_uintn(uint8_t **ptr, uint64_t var);
void serialize_uint32(uint8_t **ptr, uint32_t var);
void serialize_boolean(uint8_t **ptr, bool var);
void serialize_command(uint8_t **ptr, command_t cmd);
void serialize_guid(uint8_t **ptr, EFI_GUID *Guid);
void unserialize_data(uint8_t **ptr, void *Data, uint64_t *DataSize);
uint64_t unserialize_uintn(uint8_t **ptr);
uint32_t unserialize_uint32(uint8_t **ptr);
uint64_t unserialize_uint64(uint8_t **ptr);
void unserialize_guid(uint8_t **ptr, EFI_GUID *Guid);
int unserialize_name(uint8_t **ptr, void *buf, size_t buflen);
EFI_STATUS unserialize_result(uint8_t **ptr);

#endif // __H_SERIALIZER
