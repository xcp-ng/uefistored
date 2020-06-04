#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "backends/backend.h"
#include "backends/ramdb.h"
#include "common.h"

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

void ramdb_deinit(void)
{
}

void ramdb_destroy(void)
{
    total = 0;
    iter = 0;
    memset(variables, 0, sizeof(variables));
}

int ramdb_get(void *varname, size_t varname_len,
              void *dest, size_t dest_len,
              size_t *len, uint32_t *attrs)
{
    int cnt;
    variable_t *var = NULL;

    if ( !varname )
        return -1;

    if ( !len )
        return -1;

    cnt = 0;
    for_each_variable(variables, var)
    {
        cnt++;

        if ( varname_len != var->namesz )
            continue;

        if ( memcmp(&var->name, varname, var->namesz) == 0 )
            break;
    }

    if ( cnt > total )
        return -1;

    if ( !var || var == &variables[MAX_VAR_COUNT])
        return -1;

    if ( dest_len < var->datasz )
    {
        ERROR("The dest_len (%lu) passed to %s was too small\n", dest_len, __func__);
        return -1;
    }

    memcpy(dest, var->data, var->datasz);
    *len = var->datasz;
    *attrs = var->attrs;

    return 0;
}

int ramdb_set(void *varname, size_t varlen, void *val, size_t len, uint32_t attrs)
{
    variable_t *var;

    if ( !varname )
        return -1;

    if ( len <= 0 )
        return -1;

    if ( varlen >=  MAX_VARNAME_SZ )
        return -ENOMEM;

    if ( len >=  MAX_VARDATA_SZ )
        return -ENOMEM;

    /* If it already exists, replace it */
    for_each_variable(variables, var)
    {
        if ( var->namesz != varlen )
            continue;

        if ( memcmp(var->name, varname, varlen) == 0 )
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
        if ( variable_is_empty(var) )
        {
            memcpy(var->name, varname, varlen);
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
    iter = NULL;
    return 0;
}

struct backend ramdb_backend = {
    .init = ramdb_init,
    .deinit = ramdb_deinit,
    .get = ramdb_get,
    .set = ramdb_set,
    .destroy = ramdb_destroy,
    .next = ramdb_next,
};
