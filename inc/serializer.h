#ifndef __H_SERIALIZER_
#define __H_SERIALIZER_

#include <stdbool.h>
#include <stdint.h>
#include "uefitypes.h"
#include "common.h"

void serialize_name(uint8_t **ptr, UTF16 *VariableName);
void serialize_data(uint8_t **ptr, void *Data, uint64_t DataSize);
void serialize_uintn(uint8_t **ptr, uint64_t var);
void serialize_uint32(uint8_t **ptr, uint32_t var);
void serialize_boolean(uint8_t **ptr, bool var);
void serialize_command(uint8_t **ptr, command_t cmd);
void serialize_guid(uint8_t **ptr, EFI_GUID *Guid);
void serialize_result(uint8_t **ptr, EFI_STATUS status);
int serialize_var(uint8_t **p, size_t n, variable_t *var);
int unserialize_data(uint8_t **ptr, void *data, size_t max);
uint64_t unserialize_uintn(uint8_t **ptr);
uint32_t unserialize_uint32(uint8_t **ptr);
uint64_t unserialize_uint64(uint8_t **ptr);
void unserialize_guid(uint8_t **ptr, EFI_GUID *Guid);
int unserialize_name(uint8_t **ptr, void *buf, size_t buflen);
bool unserialize_boolean(uint8_t **ptr);
EFI_STATUS unserialize_result(uint8_t **ptr);

#endif // __H_SERIALIZER_
