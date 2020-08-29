#ifndef __H_XAPI_
#define __H_XAPI_

#include "common.h"
#include <stdint.h>

#define BIG_MESSAGE_SIZE (64 * PAGE_SIZE)

int xapi_init(bool);
int xapi_set_efi_vars(void);
int xapi_connect(void);
int xapi_efi_vars(variable_t *variables, size_t sz);
int xapi_parse_arg(char *arg);

int xapi_variables_request(variable_t *variables, size_t n);
int xapi_variables_read_file(variable_t *vars, size_t n, char *fname);

int xapi_write_save_file(void);
void xapi_cleanup(void);

/* Helpers */
int from_bytes_to_vars(variable_t *vars, size_t n, const uint8_t *bytes,
                       size_t bytes_sz);
int base64_to_bytes(uint8_t *plaintext, size_t n, char *encoded,
                    size_t encoded_size);
char *bytes_to_base64(uint8_t *buffer, size_t length);
size_t list_size(variable_t *variables, size_t n);
int base64_from_response_body(char *buffer, size_t n, char *body);
int base64_from_response(char *buffer, size_t n, char *response);

#endif // __H_XAPI_
