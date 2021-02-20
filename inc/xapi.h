#ifndef __H_XAPI_
#define __H_XAPI_

#include "common.h"
#include "variable.h"
#include <stdint.h>

#define MSG_SIZE (64 * PAGE_SIZE)

int xapi_init(bool);
int xapi_set(void);
int xapi_connect(void);
int xapi_parse_arg(char *arg);
int xapi_variables_request(variable_t *variables, size_t n);
int xapi_variables_read_file(variable_t *vars, size_t n, char *fname);
int xapi_write_save_file(void);
int xapi_sb_notify(void);
void xapi_cleanup(void);

/* global for testing */
size_t list_size(variable_t *variables, size_t n);
int base64_from_response_body(char *buffer, size_t n, char *body);
int base64_from_response(char *buffer, size_t n, char *response);

#endif // __H_XAPI_
