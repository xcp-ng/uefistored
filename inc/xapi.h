#ifndef __H_XAPI_
#define __H_XAPI_

#include "common.h"

#define BIG_MESSAGE_SIZE (8 * PAGE_SIZE)

int xapi_init(void);
int xapi_set_efi_vars(void);
int xapi_connect(void);
int xapi_efi_vars(variable_t *variables, size_t sz);
int xapi_get_efi_vars(variable_t *variables, size_t n);
int xapi_vm_get_by_uuid(char *session_id);
int xapi_parse_arg(char *arg);

/* Helpers */
int from_blob_to_vars(variable_t *vars, size_t n, uint8_t *blob, size_t blob_sz);
int base64_to_blob(uint8_t *plaintext, size_t n, char *encoded, size_t encoded_size);
char *blob_to_base64(uint8_t *buffer, size_t length);
size_t list_size(variable_t *variables, size_t n);
int base64_from_response_body(char *buffer, size_t n, char *body);
int base64_from_response(char *buffer, size_t n, char *response);

#endif // __H_XAPI_
