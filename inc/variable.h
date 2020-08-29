#ifndef __H_VARIABLE_
#define __H_VARIABLE_

#include <stdint.h>
#include <stdbool.h>
#include "uefi/types.h"

typedef struct {
    /* namesz is not strictly needed, but we use it to speed up comparisons */
    uint64_t namesz;

    /* The variable name */
    UTF16 *name;

    /* The size of the variable's data or value */
    uint64_t datasz;

    /* Pointer to the data itself */
    uint8_t *data;

    /* The variable GUID */
    EFI_GUID guid;

    /* The variable attributes */
    uint32_t attrs;
} variable_t;

#define for_each_variable(vars, var)                                           \
    for ((var) = (vars);                                                       \
         (var) < &((vars)[sizeof((vars)) / sizeof((vars)[0])]); (var)++)

variable_t *variable_create(const UTF16 *name, const uint8_t *data,
                            const uint64_t datasz, const EFI_GUID *guid,
                            const uint32_t attrs);

int variable_create_noalloc(variable_t *var, const UTF16 *name,
                            const uint8_t *data, const uint64_t datasz,
                            const EFI_GUID *guid, const uint32_t attrs);

void variable_destroy(variable_t *var);
void variable_destroy_noalloc(variable_t *var);

int variable_copy(variable_t *dst, const variable_t *src);
bool variable_eq(const variable_t *a, const variable_t *b);

int variable_set_attrs(variable_t *var, const uint32_t attrs);
int variable_set_data(variable_t *var, const uint8_t *data,
                      const uint64_t datasz);
int variable_set_guid(variable_t *var, const EFI_GUID *guid);
int variable_set_name(variable_t *var, const UTF16 *name);
void variable_printf(const variable_t *var);
uint64_t variable_size(const variable_t *var);
variable_t *variable_create_unserialize(const uint8_t **ptr);
EFI_STATUS storage_iter(variable_t *var);

#define variable_is_valid(var) \
    ((var)->name && (var)->name[0] && (var)->namesz != 0)

#endif // __H_VARIABLE_
