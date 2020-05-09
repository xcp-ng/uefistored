#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "backends/filedb.h"
#include "common.h"
#include "kissdb/kissdb.h"

static bool initialized;
static bool iter_initialized;

static KISSDB db;
static KISSDB db_var_len;
static KISSDB db_var_attrs;

static char dbpath_copy[PATH_MAX];
static char varlenpath_copy[PATH_MAX];
static char attrspath_copy[PATH_MAX];

int filedb_init(const char *dbpath,
            const char *varlenpath,
            const char *attrspath)
{
    int ret;

    strncpy(dbpath_copy, dbpath ? dbpath : DEFAULT_DBPATH, PATH_MAX);
    strncpy(varlenpath_copy, varlenpath ? varlenpath : DEFAULT_DBPATH_VAR_LEN, PATH_MAX);
    strncpy(attrspath_copy, attrspath ? attrspath : DEFAULT_DBPATH_VAR_ATTRS, PATH_MAX);

    ret = KISSDB_open(&db, dbpath, KISSDB_OPEN_MODE_RWCREAT, 1024, FILEDB_KEY_SIZE, FILEDB_VAL_SIZE);
    if ( ret != 0 )
        return -1;

    ret = KISSDB_open(&db_var_len, varlenpath, KISSDB_OPEN_MODE_RWCREAT,
                      1024, FILEDB_KEY_SIZE, sizeof(size_t));
    if ( ret != 0 )
        goto close1;

    ret = KISSDB_open(&db_var_attrs, attrspath, KISSDB_OPEN_MODE_RWCREAT,
                      1024, FILEDB_KEY_SIZE, FILEDB_VAR_ATTRS_VAL_SIZE);
    if ( ret != 0 )
        goto close2;

    initialized = true;
    return 0;

close2:
    KISSDB_close(&db_var_len);

close1:
    KISSDB_close(&db);
    return -1;
}


void filedb_deinit(void)
{
    if ( !initialized )
        return;

    KISSDB_close(&db);
    KISSDB_close(&db_var_len);
    KISSDB_close(&db_var_attrs);
    initialized = false;
}

void filedb_destroy(void)
{
    if ( initialized )
        filedb_deinit();

    remove(dbpath_copy);
    remove(varlenpath_copy);
    remove(attrspath_copy);
}

int filedb_get(void *varname, size_t varname_len, void** dest, size_t *len, uint32_t *attrs)
{
    int ret;
    uint8_t key[FILEDB_KEY_SIZE] = {0};
    uint8_t val[FILEDB_VAL_SIZE] = {0};
    size_t tmp = 0;

    if ( !initialized )
        return -1;

    if ( !varname )
        return -1;

    if ( !len )
        return -1;

    memcpy(&key, varname, varname_len);

    /* Get the variable's value */
    ret = KISSDB_get(&db, key, &val);
    if ( ret != 0 )
    {
        ERROR("Missing in var db\n");
        return -1;
    }

    /* Get the variable's value's length */
    ret = KISSDB_get(&db_var_len, key, &tmp);
    if ( ret != 0 )
    {
        ERROR("Missing in var len db\n");
        return -1;
    }

    /* Get the variable's attrs */
    ret = KISSDB_get(&db_var_attrs, key, &attrs);
    if ( ret != 0 )
    {
        ERROR("Missing in var attrs db\n");
        return -1;
    }

    /* Copy only the correct length (from db_var_len) */
    if ( tmp == 0 )
    {
        ERROR("Failed to retrieve valid var length\n");
        return -1;
    }

    *dest = malloc(tmp);
    memcpy(*dest, val, tmp);
    *len = tmp;

    return 0;
}

int filedb_set(void *varname, size_t varlen, void *val, size_t len, uint32_t attrs)
{
    uint8_t key[FILEDB_KEY_SIZE] = {0};
    uint8_t padval[FILEDB_VAL_SIZE] = {0};
    int ret;

    if ( !initialized )
        return -1;

    if ( !varname )
        return -1;

    if ( !len )
        return -1;

    if ( varlen >=  FILEDB_KEY_SIZE )
    {
        ERROR("Variable name length exceeds db size\n");
        return -ENOMEM;
    }

    if ( len >=  FILEDB_VAL_SIZE )
    {
        ERROR("Variable data length exceeds db size\n");
        return -ENOMEM;
    }

    memcpy(&key, varname, varlen);
    memcpy(&padval, val, len);

    ret = KISSDB_put(&db, key, padval);
    if ( ret != 0 )
        return -1;

    ret = KISSDB_put(&db_var_len, key, &len);
    if ( ret != 0 )
        return -1;

    ret = KISSDB_put(&db_var_attrs, key, &attrs);
    if ( ret != 0 )
        return -1;

    return 0;
}

static KISSDB_Iterator key_dbi;

void filedb_name_iter_init(void)
{
    KISSDB_Iterator_init(&db, &key_dbi);
    iter_initialized = true;
}

int filedb_name_iter_next(filedb_name_iter_t *p)
{

    int ret;
    char valdummy[FILEDB_VAL_SIZE];

    if ( !p )
    {
        ERROR("Invalid null ptr iterator\n");
        return -1;
    }

    ret = KISSDB_Iterator_next(&key_dbi, &p->name, valdummy);
    if ( ret == 0 )
    {
        /* No more entries */
        memset(p, 0, sizeof(*p));
        return ret;
    }
    else if ( ret < 0 )
    {
        ERROR("KISSDB iterator failed\n");
        return ret;
    }

    return ret;
}

void filedb_name_iter_deinit(void)
{
    int ret;
    char valdummy[FILEDB_VAL_SIZE];
    char keydummy[FILEDB_KEY_SIZE];

    /* Run the iterator to the end or until an error */
    ret = KISSDB_Iterator_next(&key_dbi, NULL, NULL);
    while ( ret > 0 )
        ret = KISSDB_Iterator_next(&key_dbi, keydummy, valdummy);

    memset(&key_dbi, 0, sizeof(key_dbi));
    iter_initialized = false;
}


bool filedb_name_iter_initialized(void)
{
    return iter_initialized;
}
