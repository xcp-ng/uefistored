#ifndef __H_XAPI_
#define __H_XAPI_

#include "common.h"
#include <stdint.h>

int xapi_init(bool);
int xapi_set_efi_vars(void);
int xapi_connect(void);
int xapi_efi_vars(variable_t *variables, size_t sz);
int xapi_parse_arg(char *arg);
int xapi_variables_request(variable_t *variables, size_t n);
int xapi_variables_read_file(variable_t *vars, size_t n, char *fname);
int xapi_write_save_file(void);
int xapi_sb_notify(void);
void xapi_cleanup(void);

#endif // __H_XAPI_
