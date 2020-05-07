#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "parse.h"

#define COMMAND_OFFSET 4
#define NAME_LEN_OFFSET 8

#define VERSION_LEN 4
#define COMMAND_LEN 4
#define NAME_LEN_LEN 8
#define DATA_LEN_LEN 8

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

static void *get_len(void *message, size_t *outl)
{
    void *p;

    /* Point to the start of the message */
    p = message;

    /* Proceed passed the VERSION field and the COMMAND field */
    p += VERSION_LEN;
    p += COMMAND_LEN;

    /* Stop at the "Name Length" field and copy that into "len" */
    memcpy(outl, p, NAME_LEN_LEN);

    /* Proceed passed the "Name Length" field */
    p += NAME_LEN_LEN;

    return p;
}

size_t parse_variable_name_size(void *message)
{
    size_t ret;
    void *p;

    /* Point to the start of the message */
    p = message;

    /* Proceed passed the VERSION field and the COMMAND field */
    p += VERSION_LEN;
    p += COMMAND_LEN;

    memcpy(&ret, p, sizeof(ret)); 

    return ret;
}

void *parse_variable_name_next(void *message, void **variable_name, size_t *outl)
{
    size_t len;
    void *copy;
    void *p;

    /* Point to the start of the message */
    p = message;

    /* Proceed passed the VERSION field and the COMMAND field */
    p += VERSION_LEN;
    p += COMMAND_LEN;

    /* Proceed passed VariableNameSize (UINTN) */
    p += 8;

    /* Stop at the "Name Length" field and copy that into "len" */
    memcpy(&len, p, NAME_LEN_LEN);

    /* Proceed passed the "Name Length" field */
    p += NAME_LEN_LEN;

    /* Stop at the "Variable Name" field and copy the name into "variable_name" */
    copy = malloc(len);
    memcpy(copy, p, len);

    /* Output data */
    *variable_name = copy;
    *outl = len;

    /* Advance pointer for next field */
    p += len;
    return p;
}

void *parse_variable_name(void *message, void **variable_name, size_t *outl)
{
    size_t len;
    void *copy;
    void *p;

    /* Advance pointer passed Name Length */
    p = get_len(message, &len);

    /* Stop at the "Variable Name" field and copy the name into "variable_name" */
    copy = malloc(len);
    memcpy(copy, p, len);

    /* Output data */
    *variable_name = copy;
    *outl = len;

    /* Advance pointer for next field */
    p += len;
    return p;
}

void *parse_guid(void *message, uint8_t guid[16])
{
    size_t len;
    void *p;

    /* Advance pointer passed Name Length */
    p = get_len(message, &len);

    /* Advance pointer to GUID field */
    p += len;

    memcpy(guid, p, 16);

    /* Advance pointer for next field */
    p += 16;
    return p;
}

uint64_t parse_datalen(void *message)
{
    size_t off;
    size_t namelen;
    size_t datalen;
    void *p = message;

    /* Proceed passed the VERSION field and the COMMAND field */
    p += VERSION_LEN;
    p += COMMAND_LEN;

    /* Stop at the "Name Length" field and copy that into "len" */
    memcpy(&namelen, p, sizeof(namelen));

    /* Proceed passed the "Name Length" field */
    p += sizeof(namelen);

    /* Proceed passed the "Name" field */
    p += namelen;

    /* Proceed passed the "GUID" field */
    p += 16;

    off = COMMAND_LEN + VERSION_LEN + sizeof(namelen) + namelen + 16;
    memcpy(&datalen, p, sizeof(datalen));
    printf("parse_datalen: off %lu\n", off);
    printf("datalen: val %lu\n", datalen);
    return datalen;
}

void *parse_data(void *message, void **data, size_t *outl)
{
    size_t len;
    void *buf, *p;

    /* Advance pointer passed Name Length to Name field */
    p = get_len(message, &len);

    /* Advance pointer passed Name field to GUID field */
    p += len;

    /* Advance pointer passed GUID field to Data Length field */
    p += 16;

    /* Copy Data Length */
    memcpy(&len, p, DATA_LEN_LEN);

    /* Advance pointer to Data field */
    p += DATA_LEN_LEN;

    /* Copy Data field */
    buf = malloc(len);
    memcpy(buf, p, len);

    /* Output data */
    *outl = len;
    *data = buf;

    p += len;

    return p;
}

uint32_t parse_attrs(void *message)
{
    uint32_t ret;
    void *p;
    size_t len;

    /* Advance pointer passed Name Length to Name field */
    p = get_len(message, &len);

    /* Advance pointer passed Name field to GUID field */
    p += len;

    /* Advance pointer passed GUID field to Data Length field */
    p += 16;

    /* Copy Data Length */
    memcpy(&len, p, DATA_LEN_LEN);

    /* Advance pointer to Data field */
    p += DATA_LEN_LEN;

    /* Advance passed Data field to Attr field */
    p += len;

    memcpy(&ret, p, sizeof(ret));
    return ret;
}

uint8_t parse_efiruntime(void *message)
{
    void *p;
    size_t len;

    /* Advance pointer passed Name Length to Name field */
    p = get_len(message, &len);

    /* Advance pointer passed Name field to GUID field */
    p += len;

    /* Advance pointer passed GUID field to Data Length field */
    p += 16;

    /* Copy Data Length */
    memcpy(&len, p, DATA_LEN_LEN);

    /* Advance pointer to Data field */
    p += DATA_LEN_LEN;

    /* Advance passed Data field to Attr field */
    p += len;

    /* Advance passed Attr field */
    p += 4;

    return *((uint8_t*)p);
}
