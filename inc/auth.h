#ifndef __H__AUTH_
#define __H__AUTH_

#include <stdint.h>
#include "uefi/types.h"

EFI_STATUS process_variable(UTF16 *name, EFI_GUID *guid,
                            void *data, uint64_t data_size,
                            uint32_t attrs);

#endif // __H__AUTH_
