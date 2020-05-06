#ifndef __H_COMMAND_
#define __H_COMMAND_

#include <stdint.h>

#include "xenvar.h"

command_t parse_command(void *comm_buff);
uint32_t parse_version(void *comm_buff);
void *parse_variable_name(void *comm_buff, void **variable_name, size_t *len);
void *parse_variable_name_next(void *comm_buff, void **variable_name, size_t *outl);
size_t parse_variable_name_size(void *comm_buff);
void *parse_guid(void *comm_buff, uint8_t guid[16]);
void *parse_data(void *comm_buff, void **data, size_t *outl);
uint32_t parse_attrs(void *comm_buff);
uint8_t parse_efiruntime(void *comm_buff);
uint64_t parse_datalen(void *comm_buff);

#endif
