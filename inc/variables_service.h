#ifndef __H_VARIABLES_SERVICE__
#define __H_VARIABLES_SERVICE__

#include <stdint.h>

#include "uefi/types.h"

/* Public for unit tests */
EFI_STATUS evaluate_attrs(uint32_t attrs);
void set_efi_runtime(bool runtime);

#endif // __H_VARIABLES_SERVICE__
