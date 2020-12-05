#ifndef __H__AUTH_
#define __H__AUTH_

#include <stdint.h>
#include "uefi/types.h"
#include "uefi/image_authentication.h"

EFI_STATUS process_variable(UTF16 *name, size_t namesz, EFI_GUID *guid,
                            void *data, uint64_t data_size,
                            uint32_t attrs);

EFI_STATUS auth_internal_find_variable(UTF16 *name, EFI_GUID *guid,
                                           void **data, uint64_t *data_size);

EFI_STATUS process_var_with_pk(UTF16 *name, size_t namesz, EFI_GUID *guid, void *data,
                            uint64_t data_size, uint32_t attrs, bool is_pk);

EFI_STATUS process_var_with_kek(UTF16 *name, size_t namesz, EFI_GUID *guid, void *data,
                             uint64_t data_size, uint32_t attrs);

bool cert_equals_esl(uint8_t *cert_der, uint32_t cert_size, EFI_SIGNATURE_LIST *old_esl);

EFI_STATUS update_platform_mode(uint32_t mode);

#endif // __H__AUTH_
