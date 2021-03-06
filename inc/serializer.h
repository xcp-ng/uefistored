#ifndef __H_SERIALIZER_
#define __H_SERIALIZER_

#include <stdbool.h>
#include <stdint.h>

#include "uefi/types.h"
#include "barrier.h"
#include "common.h"
#include "variable.h"

struct variable_list_header {
    uint32_t magic;
    uint32_t version;
    uint64_t variable_count;
    uint64_t payload_size;
};

void serialize_name(uint8_t **ptr, const UTF16 *name, size_t namesz);
void serialize_data(uint8_t **ptr, const void *data, uint64_t datasz);
void serialize_uintn(uint8_t **ptr, uint64_t var);
void serialize_uint32(uint8_t **ptr, uint32_t var);
void serialize_uint64(uint8_t **ptr, uint64_t var);
void serialize_boolean(uint8_t **ptr, bool var);
void serialize_command(uint8_t **ptr, command_t cmd);
void serialize_guid(uint8_t **ptr, const EFI_GUID *guid);
void serialize_result(uint8_t **ptr, EFI_STATUS status);
int serialize_var(uint8_t **p, const variable_t *var);
int serialize_variable_list(uint8_t **ptr, size_t sz, const variable_t *var,
                            size_t n);
ssize_t unserialize_data(const uint8_t **ptr, void *data, size_t max);
uint64_t unserialize_uintn(const uint8_t **ptr);
uint32_t unserialize_uint32(const uint8_t **ptr);
uint64_t unserialize_uint64(const uint8_t **ptr);
void unserialize_guid(const uint8_t **ptr, EFI_GUID *Guid);
uint64_t unserialize_namesz(const uint8_t **ptr);
bool unserialize_boolean(const uint8_t **ptr);
EFI_STATUS unserialize_result(const uint8_t **ptr);
void unserialize_variable_list_header(const uint8_t **ptr,
                                      struct variable_list_header *hdr);
int unserialize_var_cached(const uint8_t **ptr, variable_t *var);
void unserialize_timestamp(const uint8_t **p, EFI_TIME *timestamp);
void unserialize_cert(const uint8_t **ptr, uint8_t cert[SHA256_DIGEST_SIZE]);

#endif // __H_SERIALIZER_
