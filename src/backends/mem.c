#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "backends/mem.h"
#include "common.h"
#include "kissdb/kissdb.h"

/**
 * This is a super simple backend for varstored.  It simply uses
 * a file-backed key-value store to maintain UEFI variables.
 *
 * Two DBs are used.  One maps the variable name to the variable value.
 * The other maps the variable name to the variable value len.
 * This is required because KISSDB only accepts fixed-length keys and values.
 */

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DBPATH "/var/run/xen/varstored-db.dat"
#define DBPATH_VAR_LEN "/var/run/xen/varstored-db-var-len.dat"
#define ENTRY_LEN 1024

#define KISSDB_KEY_SIZE 128 
#define KISSDB_VAL_SIZE 1024

static KISSDB db;
static KISSDB db_var_len;

int db_init(void)
{
    int ret;
    ret = KISSDB_open(&db, DBPATH, KISSDB_OPEN_MODE_RWCREAT, 1024, KISSDB_KEY_SIZE, KISSDB_VAL_SIZE);

    if ( ret < 0 )
        return ret;

    return  KISSDB_open(&db_var_len, DBPATH_VAR_LEN, KISSDB_OPEN_MODE_RWCREAT, 1024, KISSDB_KEY_SIZE, sizeof(size_t));
}

void db_deinit(void)
{
    KISSDB_close(&db);
    KISSDB_close(&db_var_len);
}

int db_get(void *varname, size_t varname_len, void** dest, size_t *len)
{
    uint8_t key[KISSDB_KEY_SIZE] = {0};
    uint8_t val[KISSDB_VAL_SIZE] = {0};
    size_t tmp;

    if ( !varname )
        return -1;

    if ( !len )
        return -1;

    memcpy(&key, varname, varname_len);

    /* Get the variable's value */
    KISSDB_get(&db, key, &val);

    /* Get the variable's value's length */
    KISSDB_get(&db_var_len, key, &tmp);

    /* Copy only the correct length (from db_var_len) */
    *dest = malloc(tmp);
    memcpy(*dest, val, tmp);
    *len = tmp;

    return 0;
}

int db_set(void *varname, size_t varlen, void *val, size_t len)
{
    uint8_t key[KISSDB_KEY_SIZE] = {0};
    uint8_t padval[KISSDB_VAL_SIZE] = {0};
    int ret;

    if ( !varname )
        return -1;

    if ( !len )
        return -1;

    if ( varlen >=  KISSDB_KEY_SIZE )
    {
        ERROR("Variable name length exceeds db size\n");
        return -1;
    }

    if ( len >=  KISSDB_VAL_SIZE )
    {
        ERROR("Variable name length exceeds db size\n");
        return -1;
    }

    memcpy(&key, varname, varlen);
    memcpy(&padval, val, len);

    ret = KISSDB_put(&db, key, padval);
    if ( ret < 0 )
        return ret;

    ret = KISSDB_put(&db_var_len, key, &len);
    if ( ret < 0 )
        return ret;

    return 0;
}

int db_save(void)
{
    return -1;
}
