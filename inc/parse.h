#ifndef __H_COMMAND_
#define __H_COMMAND_

#include <stdint.h>

typedef enum command {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
    COMMAND_NOTIFY_SB_FAILURE,
} command_t;

command_t parse_command(void *message);
uint32_t parse_version(void *message);
void *parse_variable_name(void *message, void **variable_name, size_t *len);
void *parse_guid(void *message, uint8_t guid[16]);
void *parse_data(void *message, void **data, size_t *outl);
uint32_t parse_attrs(void *message);
uint8_t parse_efiruntime(void *message);
uint64_t parse_datalen(void *message);

#endif
