#ifndef __H_VARIABLE_
#define __H_VARIABLE_

#include <stdint.h>
#include <stdbool.h>

#include "config.h"
#include "uefi/types.h"

#define SHA256_DIGEST_SIZE 32

typedef struct variable {
    /* The variable name */
    UTF16 name[MAX_VARIABLE_NAME_CHARS];

    /* namesz is not strictly needed, but we use it to speed up comparisons */
    uint64_t namesz;

    /* Pointer to the data itself */
    uint8_t *data;

    /* The size of the variable's data or value */
    uint64_t datasz;

    /* The variable GUID */
    EFI_GUID guid;

    /* The variable attributes */
    uint32_t attrs;

    /* EFI timestamp for time based auth */
    EFI_TIME timestamp;

    /* SHA-256 digest of signer's CN and top-level tbs cert */
    uint8_t cert[SHA256_DIGEST_SIZE];
} variable_t;

#define ARRAY_SIZE(array) (sizeof((array)) / sizeof((array)[0]))

#define for_each_variable(vars, var, __i)                              \
        for (__i=0; __i<ARRAY_SIZE(vars) && ((var = &vars[__i]) || true); __i++)

variable_t *variable_create(const UTF16 *name, size_t namesz, const uint8_t *data,
                            const uint64_t datasz, const EFI_GUID *guid,
                            const uint32_t attrs);

int variable_create_noalloc(variable_t *var, const UTF16 *name, size_t namesz,
                            const uint8_t *data, const uint64_t datasz,
                            const EFI_GUID *guid, const uint32_t attrs,
                            const EFI_TIME *timestamp);

void variable_destroy(variable_t *var);
void variable_destroy_noalloc(variable_t *var);

int variable_copy(variable_t *dst, const variable_t *src);
bool variable_eq(const variable_t *a, const variable_t *b);

int variable_set_attrs(variable_t *var, const uint32_t attrs);
int variable_set_data(variable_t *var, const uint8_t *data, uint64_t datasz);
int variable_set_guid(variable_t *var, const EFI_GUID *guid);
int variable_set_name(variable_t *var, const UTF16 *name, size_t namesz);
int variable_set_timestamp(variable_t *var, const EFI_TIME *timestamp);
uint64_t variable_size(const variable_t *var);
variable_t *variable_create_unserialize(const uint8_t **ptr);

int from_bytes_to_vars(variable_t *vars, size_t n, const uint8_t *bytes);

static inline bool variable_is_valid(const variable_t *var) {
    return (var && var->name && var->name[0] && var->namesz != 0);
}

variable_t *find_variable(const UTF16 *name, size_t namesz, const EFI_GUID *guid,
                          variable_t variables[MAX_VAR_COUNT], size_t n);

/* Get the namesz with no end of string char '\0' */
#define variable_serialized_namesz(var) ((var)->namesz)

#endif // __H_VARIABLE_
