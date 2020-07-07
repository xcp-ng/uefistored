#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "backends/ramdb.h"
#include "common.h"
#include "uefitypes.h"
#include "log.h"

#define MAX_VARNAME_SZ 128 
#define MAX_VARDATA_SZ 1024

static variable_t variables[MAX_VAR_COUNT];
static size_t iter;
static size_t total;

int ramdb_init(void)
{
    total = 0;
    iter = 0;
    memset(variables, 0, sizeof(variables));
    return 0;
}

size_t ramdb_count(void)
{
	return total;
}

void ramdb_deinit(void)
{
}

void ramdb_destroy(void)
{
    total = 0;
    iter = 0;
    memset(variables, 0, sizeof(variables));
}

int ramdb_exists(const UTF16 *name)
{
    variable_t *var = NULL;

    var = find_variable(name, variables, MAX_VAR_COUNT);

    if ( !var )
        return VAR_NOT_FOUND;

    return 0;
}

int ramdb_get(const UTF16 *name,
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

int ramdb_remove(const UTF16 *name)
{
    size_t varlen;
    variable_t *var;

    if ( !name )
        return -1;

    varlen = strlen16(name);

    for_each_variable(variables, var)
    {
        if ( var->namesz != varlen )
            continue;

        if ( strcmp16(var->name, name) == 0 )
        {
            memset(var, 0, sizeof(*var));
	    total--;
            return 0;
        }
    }

    /* Not found */
    return 0;
}

int ramdb_set(const UTF16 *name, const void *val, const size_t len, const uint32_t attrs)
{
    size_t varlen;
    variable_t *var;

    if ( !name )
        return -1;

    varlen = strlen16(name);

    if ( varlen + 2 >=  MAX_VARNAME_SZ )
        return -ENOMEM;

    if ( len >=  MAX_VARDATA_SZ )
        return -ENOMEM;

    /* As specified by the UEFI spec */
    if ( len == 0 || attrs == 0 )
        return ramdb_remove(name);

    /* If it already exists, replace it */
    for_each_variable(variables, var)
    {
        if ( var->namesz != varlen )
            continue;

        if ( strcmp16(var->name, name) == 0 )
        {
            memcpy(var->data, val, len);
            memcpy(&var->namesz, &varlen, sizeof(var->namesz));
            memcpy(&var->datasz, &len, sizeof(var->datasz));
            memcpy(&var->attrs, &attrs, sizeof(var->attrs));
            return 0;
        }
    }

    /* Place it in first found empty slot */
    for_each_variable(variables, var)
    {
        if ( var->namesz == 0 )
        {
            if ( strncpy16(var->name, name, MAX_VARNAME_SZ) < 0 )
            {
                memset(var->name, 0, MAX_VARNAME_SZ * sizeof(UTF16));
                return -1;
            }
                
            memcpy(var->name, name, varlen);
            memcpy(var->data, val, len);
            memcpy(&var->namesz, &varlen, sizeof(var->namesz));
            memcpy(&var->datasz, &len, sizeof(var->datasz));
            memcpy(&var->attrs, &attrs, sizeof(var->attrs));
            total++;
            return 0;
        }
    }

    return -1;
}

/**
 * Get the next variable in the DB
 *
 * @current: the current variable (provided by the caller)
 * @next: the next variable (loaded by this function)
 *
 * Returns -1 on error, 0 on end of list, 1 on success
 */
int ramdb_next(variable_t *current, variable_t *next)
{
    variable_t *var;

    if ( !current || !next )
        return -1;

    if ( iter >= MAX_VAR_COUNT || iter >= total )
        goto stop_iterator;

    var = &variables[iter];
    
    /* First call */
    if ( iter == 0 )
    {

        if ( variable_is_empty(var) )
            goto stop_iterator;

        goto variable_found;
    }

variable_found:
    memcpy(next, var, sizeof(*next));
    iter++;
    return 1;

stop_iterator:
    iter = 0;
    return 0;
}

void ramdb_debug(void)
{
#if 1
    variable_t *var;

    for_each_variable(variables, var) 
    {
        if ( variable_is_empty(var) )
            continue;

        char ascii[MAX_VARNAME_SZ];
        uc2_ascii(var->name, ascii, MAX_VARNAME_SZ);

        switch ( var->datasz )
        {
        case 1:
            DEBUG("%s: 0x%x\n", ascii, *((uint8_t*)var->data));
            break;
        case 2:
            DEBUG("%s: 0x%x\n", ascii, *((uint16_t*)var->data));
            break;
        case 4:
            DEBUG("%s: 0x%x\n", ascii, *((uint32_t*)var->data));
            break;
        case 8:
            DEBUG("%s: 0x%lx\n", ascii, *((uint64_t*)var->data));
            break;
        case 16:
            DEBUG("%s: 0x%llx\n", ascii, *((unsigned long long*)var->data));
            break;
        default:
        {
            DPRINTF("%s: ", ascii);
            dprint_data(var->data, var->datasz);
            break;
        }
        }
    }
#endif
}
