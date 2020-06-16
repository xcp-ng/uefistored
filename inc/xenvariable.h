#ifndef __H_XENVARIABLE_
#define __H_XENVARIABLE_

#include "uefitypes.h"
#include "common.h"
#include <stdint.h>

int xenvariable_init(var_initializer_t init_vars);
void xenvariable_handle_request(void *comm_buff);

EFI_STATUS set_variable(UTF16 *variable, EFI_GUID *guid,
                        uint32_t attrs, size_t datalen,
                        void *data);

EFI_STATUS get_variable(UTF16 *variable,
                        EFI_GUID *guid,
                        uint32_t *attrs,
                        size_t *size,
                        void *data);

int xenvariable_deinit(void);

#endif // __H_XENVARIABLE_
