#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "storage.h"
#include "uefi/types.h"
#include "serializer.h"
#include "variable.h"

int variable_set_attrs(variable_t *var, const uint32_t attrs)
{
    if ( !var )
        return -1;

    var->attrs = attrs;

    return 0;
}

int variable_set_data(variable_t *var, const uint8_t *data, const uint64_t datasz)
{
    uint8_t *new = NULL;

    if ( !var || !data || datasz == 0 )
        return -1;

    if ( datasz == 0 )
        return -1;

    if ( var->datasz != datasz )
    {
        
        new = malloc(datasz);

        if ( !new )
            return -1;

        if ( var->data )
        {
            free(var->data);
        }

        var->data = new;
    }

    if ( !var->data )
    {
        var->data = malloc(datasz);

        if ( !var->data )
            return -1;
    }

    memcpy(var->data, data, datasz);
    var->datasz = datasz;

    return 0;
}

int variable_set_guid(variable_t *var, const EFI_GUID *guid)
{
    if ( !var || !guid )
        return -1;

    memcpy(&var->guid, guid, sizeof(var->guid));

    return 0;
}

int variable_set_name(variable_t *var, const UTF16 *name)
{
    UTF16 *new = NULL;
    uint64_t namesz;

    if ( !var || !name )
        return -1;

    namesz = strsize16(name);

    if ( namesz == 0 )
        return -1;

    if ( var->namesz != namesz )
    {
        new = malloc(namesz + sizeof(UTF16));

        if ( !new )
            return -1;

        if ( var->name )
            free(var->name);

        var->name = new;
    }

    if ( !var->name )
    {
        var->name = malloc(namesz + sizeof(UTF16));
        if ( !var->name )
            return -1;
    }

    strncpy16(var->name, name, namesz + sizeof(UTF16));
    var->namesz = namesz;

    return 0;
}

variable_t *variable_create(const UTF16 *name, const uint8_t *data,
                            const uint64_t datasz, const EFI_GUID *guid,
                            const uint32_t attrs)
{
    int ret;
    variable_t *var;

    if ( !name || !data || !guid || datasz == 0 )
        return NULL;

    var = calloc(1, sizeof(variable_t));

    if ( !var )
        return NULL;

    ret = variable_set_name(var, name);
    
	if ( ret < 0 )
    {
        free(var);
        return NULL;
    }

    ret = variable_set_data(var, data, datasz);

    if ( ret < 0 )
    {
        free(var->name);
        free(var);
        return NULL;
    }

    memcpy(&var->guid, guid, sizeof(var->guid));
    var->attrs = attrs;

	return var;
}

/**
 * Returns a variable_t ptr created from a byte serialization.
 *
 * Unlike other unserialize_* functions, the return pointer
 * must be freed by the caller.
 */
variable_t *variable_create_unserialize(uint8_t **ptr)
{
    variable_t *var;
    UTF16 name[MAX_VARIABLE_NAME_SIZE] = {0};
    EFI_GUID guid;
    uint8_t *data;
    uint64_t namesz, datasz;
    uint32_t attrs;

	if ( !ptr )
		return NULL;

    namesz = unserialize_uint64(ptr);

	if ( namesz == 0 )
        return NULL;

	memcpy(name, *ptr, namesz);
	*ptr += namesz;

    datasz = unserialize_uint64(ptr);

	if ( datasz == 0 )
		return NULL;

	data = malloc(datasz);

    if ( !data )
        return NULL;

    memcpy(data, *ptr, datasz);
    *ptr += datasz;

    unserialize_guid(ptr, &guid);
    attrs = unserialize_uint32(ptr);

    *ptr += VAR_PADDING;

    var = variable_create(name, data, datasz, &guid, attrs);
    free(data);
    return var;
}


int variable_create_noalloc(variable_t *var, const UTF16 *name,
                            const uint8_t *data, const uint64_t datasz,
                            const EFI_GUID *guid, const uint32_t attrs)
{
    if ( !var || !name || !data || !guid || datasz == 0 )
        return -1;

    if ( variable_set_name(var, name) < 0 )
        return -1;

    if ( variable_set_data(var, data, datasz) < 0 )
        goto cleanup_name;

    if ( variable_set_guid(var, guid) < 0 )
        goto cleanup_data;

    if ( variable_set_attrs(var, attrs) < 0 )
        goto cleanup_data;

    return 0;

cleanup_data:
    free(var->data);

cleanup_name:
    free(var->name);
    return -1;

}

void variable_destroy_noalloc(variable_t *var)
{
    if ( !var )
        return;
    
    if ( var->name )
    {
        free(var->name);
        var->name = NULL;
    }

    if ( var->data)
    {
        free(var->data);
        var->data = NULL;
    }
}

void variable_destroy(variable_t *var)
{
    if ( !var )
        return;

    variable_destroy_noalloc(var);
    free(var);
}

int variable_copy(variable_t *dst, const variable_t *src)
{
    if ( !dst || !src )
        return -1;

    memcpy(&dst->namesz, &src->namesz, sizeof(dst->namesz));

    if ( dst->name )
    {
        free(dst->name);
        dst->name = malloc(dst->namesz + 2);
        memset(dst->name, 0, dst->namesz + 2);
    }

    memcpy(&dst->datasz, &src->datasz, sizeof(dst->datasz));
    
    if ( dst->data )
    {
        free(dst->data);
        dst->data = malloc(dst->datasz + 2);
        memset(dst->data, 0, dst->datasz + 2);
    }

    memcpy(&dst->attrs, &src->attrs, sizeof(dst->attrs));
    memcpy(&dst->guid, &src->guid, sizeof(dst->guid));

    return 0;
}

bool variable_eq(const variable_t *a, const variable_t *b)
{
    if ( !a || !b )
        return false;

    if ( a->namesz != b->namesz )
        return false;

    if ( a->datasz != b->datasz )
        return false;

    if ( strcmp16(a->name, b->name) != 0 )
        return false;

    if ( memcmp(a->data, b->data, a->datasz) != 0 )
        return false;

    /* TODO: compare attrs and guids */

    return true;
}

uint64_t variable_size(const variable_t *var)
{
    uint64_t sum;

    if ( !var )
        return 0;

    /* Name Length */
    sum = sizeof(var->namesz);

    /* Name Value */
    sum += var->namesz;

    /* Data Length */
    sum += sizeof(var->datasz);

    /* Data Value */
    sum += var->datasz;

    /* GUID Value */
    sum += sizeof(var->guid);

    /* ATTRS Value */
    sum += sizeof(var->attrs);

    return sum;
}

void variable_printf(const variable_t *var)
{
    char *data, *name;

    if ( !var )
        return;

    name = malloc(var->namesz + 2);

    if ( !name )
        return;

    memset(name, 0, (var->namesz + 2)/ sizeof(UTF16));
    uc2_ascii(var->name, name, var->namesz / sizeof(UTF16));

    data = malloc(var->datasz + 2);

    if ( !data )
        return;

    memset(data, 0, var->datasz + 2);
    uc2_ascii((UTF16*)var->data, data, var->datasz + 2);

    printf("Variable<name=%s", name);
    printf(", data(%lu)=0x%02x%02x%02x%02x", var->datasz, var->data[0],
                                             var->data[1], var->data[2], var->data[3]);
    printf(", guid=%x", var->guid.Data1);
    printf(", attrs=%x>\n", var->attrs);

    free(name);
    free(data);
}
