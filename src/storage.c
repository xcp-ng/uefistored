#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "storage.h"
#include "common.h"
#include "uefi/types.h"
#include "log.h"

#define MAX_VARNAME_SZ 128 
#define MAX_VARDATA_SZ 1024

static variable_t variables[MAX_VAR_COUNT];
static size_t iter = 0;
static size_t total = 0;
static uint64_t used = 0;

static bool slot_is_empty(variable_t *var)
{
    if ( !var || var->datasz == 0 || var->namesz == 0 )
       return true;

    return false;
}

int storage_init(void)
{
    storage_destroy();
    return 0;
}

size_t storage_count(void)
{
	return total;
}

void storage_deinit(void)
{
}

void storage_destroy(void)
{
    variable_t *var;

    total = 0;
    used = 0;
    iter = 0;

    for_each_variable(variables, var)
    {
        variable_destroy_noalloc(var);
    }

    memset(variables, 0, sizeof(variables));
}

int storage_exists(const UTF16 *name)
{
    variable_t *var = NULL;

    var = find_variable(name, variables, MAX_VAR_COUNT);

    if ( !var )
        return VAR_NOT_FOUND;

    return 0;
}

int storage_get(const UTF16 *name,
              void *dest, size_t n,
              size_t *len, uint32_t *attrs)
{
    variable_t *var = NULL;

    if ( !name )
        return -1;

    if ( !len )
        return -1;

    *len = 0;

    var = find_variable(name, variables, MAX_VAR_COUNT);

    if ( !var )
        return VAR_NOT_FOUND;

    if ( n < var->datasz )
    {
        ERROR("The n (%lu) passed to %s was too small\n", n, __func__);
        return -1;
    }

    memcpy(dest, var->data, var->datasz);
    *len = var->datasz;
    *attrs = var->attrs;

    return 0;
}

int storage_remove(const UTF16 *name)
{
    size_t namesz;
    variable_t *var;

    if ( !name )
        return -1;

    namesz = strsize16(name);

    for_each_variable(variables, var)
    {
        if ( var->namesz != namesz )
            continue;

        if ( strcmp16(var->name, name) == 0 )
        {
            variable_destroy(var);
            used -= (var->datasz + namesz);
            total--;
            return 0;
        }
    }

    /* Not found */
    return 0;
}

int storage_set(const UTF16 *name,
              const void *data,
              const size_t datasz,
              const uint32_t attrs)
{
    int ret;
    EFI_GUID guid = {0};
    size_t namesz;
    variable_t *var;

    if ( !name || !data )
        return -1;

    namesz = strsize16(name);

    if ( namesz >= MAX_VARIABLE_NAME_SIZE )
        return -ENOMEM;

    if ( datasz >= MAX_VARIABLE_DATA_SIZE )
        return -ENOMEM;

    if ( datasz + namesz + storage_used() > MAX_STORAGE_SIZE )
        return -ENOMEM;

    /* As specified by the UEFI spec */
    if ( datasz == 0 || attrs == 0 )
        return storage_remove(name);

    /* If it already exists, replace it */
    for_each_variable(variables, var)
    {
        if ( var->namesz != namesz )
            continue;

        if ( strcmp16(var->name, name) == 0 )
        {
            ret = variable_set_name(var, name);

            if ( ret < 0 )
                return ret;

            ret = variable_set_data(var, data, datasz);

            if ( ret < 0 )
                return ret;

            memcpy(&var->attrs, &attrs, sizeof(var->attrs));
            return 0;
        }
    }

    /* If it is completely new, place it in the first found empty slot */
    for_each_variable(variables, var)
    {
        if ( var->name == NULL )
        {
            ret = variable_create_noalloc(var, name, data, datasz, &guid, attrs);

            if ( ret < 0 )
                return ret;

            total++;
            used += datasz + namesz;
            return 0;
        }
    }

    return -1;
}

uint64_t storage_used(void)
{
    return used;
}

/**
 * Get the next variable in the DB
 *
 * @current: the current variable (provided by the caller)
 * @next: the next variable (loaded by this function)
 *
 * Returns -1 on error, 0 on end of list, 1 on success
 */
int storage_next(variable_t *next)
{
    variable_t *var;

    if ( !next )
        return -1;

    if ( iter >= MAX_VAR_COUNT || total == 0 )
        goto stop_iterator;
    
    var = &variables[iter];

    /* Find next non-empty_variable slot */
    while ( iter < MAX_VAR_COUNT && slot_is_empty(var) )
    {
        iter++;
        var = &variables[iter];
    }

    /* If none found, stop the iteration */
    if ( iter >= MAX_VAR_COUNT )
        goto stop_iterator;

    iter++;

    /* A variable has been found so return it as next */
    variable_create_noalloc(next, var->name, var->data, var->datasz, &var->guid, var->attrs);
    return 1;

stop_iterator:
    iter = 0;
    return 0;
}
