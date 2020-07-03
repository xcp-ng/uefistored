#ifndef __H_VARIABLES_SERVICE__
#define __H_VARIABLES_SERVICE__

#include <stdint.h>

#include "uefitypes.h"

EFI_STATUS
get_variable(UTF16 *variable, EFI_GUID *guid, uint32_t *attrs, size_t *size, void *data);

EFI_STATUS
set_variable(UTF16 *variable, EFI_GUID *guid, uint32_t attrs, size_t datalen, void *data);

#endif // __H_VARIABLES_SERVICE__
