#ifndef __H_XAPI_
#define __H_XAPI_

#include "common.h"

size_t xapi_serialized_size(serializable_var_t *vars, size_t);
int xapi_init(void);
int xapi_serialize(serializable_var_t *vars, size_t len, void *data, size_t size);
int xapi_set_efi_vars(void);
int xapi_connect(void);
int xapi_efi_vars(variable_t *variables, size_t sz);
int xapi_get_efi_vars(variable_t *variables, size_t n);
int xapi_vm_get_by_uuid(char *session_id);
int xapi_parse_arg(char *arg);

#endif // __H_XAPI_
