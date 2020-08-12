#ifndef __H_XEN_VARIABLE_SERVER_
#define __H_XEN_VARIABLE_SERVER_

#include "uefi/types.h"
#include "common.h"
#include <stdint.h>
#include <stdbool.h>

int xen_variable_server_init(void);
void xen_variable_server_handle_request(void *comm_buff);

EFI_STATUS set_variable(UTF16 *variable, EFI_GUID *guid,
                        uint32_t attrs, size_t datasz,
                        void *data);

EFI_STATUS get_variable(UTF16 *variable,
                        EFI_GUID *guid,
                        uint32_t *attrs,
                        size_t *size,
                        void *data);

#endif // __H_XEN_VARIABLE_SERVER_
