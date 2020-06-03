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

/* Helpers */
int from_vars_to_blob(uint8_t *buf, size_t bufsize, variable_t *vars, size_t vars_cnt);
int from_blob_to_vars(variable_t *vars, size_t n, uint8_t *blob, size_t blob_sz);
int unserialize_var(variable_t *var, uint8_t **src);
int serialize_var(uint8_t **p, size_t n, variable_t *var);
int base64_to_blob(uint8_t *plaintext, size_t n, char *encoded, size_t encoded_size);
char *blob_to_base64(uint8_t *buffer, size_t length);
size_t blob_size(variable_t *variables, size_t n);
#endif // __H_XAPI_
