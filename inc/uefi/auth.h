#ifndef __H__AUTH_
#define __H__AUTH_

#include <stdint.h>
#include "uefi/types.h"

EFI_STATUS process_variable(UTF16 *name, EFI_GUID *guid,
                            void *data, uint64_t data_size,
                            uint32_t attrs);

EFI_STATUS
CleanCertsFromDb(void);

EFI_STATUS auth_internal_find_variable(UTF16 *name, EFI_GUID *guid,
                                           void **data, uint64_t *data_size);

EFI_STATUS process_var_with_pk(UTF16 *name, EFI_GUID *guid, void *data,
                            uint64_t data_size, uint32_t attrs, bool IsPk);

#endif // __H__AUTH_
