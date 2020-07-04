#ifndef __H_XEN_VARIABLE_SERVER_
#define __H_XEN_VARIABLE_SERVER_

#include "uefitypes.h"
#include "common.h"
#include <stdint.h>

int xen_variable_server_init(var_initializer_t init_vars);
void xen_variable_server_handle_request(void *comm_buff);

EFI_STATUS set_variable(UTF16 *variable, EFI_GUID *guid,
                        uint32_t attrs, size_t datalen,
                        void *data);

EFI_STATUS get_variable(UTF16 *variable,
                        EFI_GUID *guid,
                        uint32_t *attrs,
                        size_t *size,
                        void *data);

int xen_variable_server_deinit(void);

#endif // __H_XEN_VARIABLE_SERVER_
