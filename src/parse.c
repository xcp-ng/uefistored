#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "parse.h"

#define COMMAND_OFFSET 4
#define NAME_LEN_OFFSET 8

#define VERSION_LEN 4
#define COMMAND_LEN 4
#define NAME_LEN_LEN 8

static char __array_assert_size64[sizeof(size_t) == NAME_LEN_LEN] = { 0 };

command_t parse_command(void *message)
{
    uint32_t ret;

    memcpy(&ret, message + COMMAND_OFFSET, sizeof(ret)); 

    return ret;
}

uint32_t parse_version(void *message)
{
    uint32_t ret;

    memcpy(&ret, message, sizeof(ret)); 

    return ret;
}

void parse_variable_name(void *message, void **variable_name, size_t *outl)
{
    uint32_t ret;
    size_t len;
    void *copy;
    void *p;

    /* Point to the start of the message */
    p = message;

    /* Proceed passed the VERSION field and the COMMAND field */
    p += VERSION_LEN;
    p += COMMAND_LEN;

    /* Stop at the "Name Length" field and copy that into "len" */
    memcpy(&len, p, NAME_LEN_LEN);

    /* Proceed passed the "Name Length" field */
    p += NAME_LEN_LEN;

    /* Stop at the "Variable Name" field and copy the name into "variable_name" */
    copy = malloc(len);
    memcpy(copy, p, len);

    *variable_name = copy;
    *outl = len;
}
