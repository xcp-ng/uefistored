#ifndef __H_VARIABLES_SERVICE__
#define __H_VARIABLES_SERVICE__

#include <stdint.h>

#include "uefi/types.h"

EFI_STATUS
get_variable(UTF16 *variable, EFI_GUID *guid, uint32_t *attrs, size_t *size, void *data);

EFI_STATUS
set_variable(UTF16 *variable, EFI_GUID *guid, uint32_t attrs, size_t datasz, void *data);

EFI_STATUS query_variable_info(uint32_t attrs, 
                               uint64_t *max_variable_storage,
                               uint64_t *remaining_variable_storage,
                               uint64_t *max_variable_size);

/* Public for unit tests */
bool valid_attrs(uint32_t attrs);

#endif // __H_VARIABLES_SERVICE__
