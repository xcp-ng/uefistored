#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "backends/mem.h"
#include "common.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DBPATH "/var/run/xen/varstored-db.txt"
#define ENTRY_LEN 1024

typedef struct {
    void *var;
    size_t varlen;
    void *data;
    size_t datalen;
} entry_t;

static entry_t db[ENTRY_LEN];

int db_init(void)
{
    return 0;
}

void db_deinit(void)
{
    return;
}

int db_get(void *varname, size_t datalen, void** dest, size_t *len)
{
    int i;
    void *buf;
    entry_t *p;

    if ( !varname )
        return -1;

    for ( i=0; i<ENTRY_LEN; i++ )
    {
        p = &db[i];
        if ( p->varlen != datalen )
            continue;

        if ( memcmp(p->var, varname, p->varlen) )
            break;
    }

    /* Not found */
    if ( i == ENTRY_LEN )
    {
        DEBUG("Entry not found\n");
        return -1;
    }

    buf = malloc(p->datalen);
    
    if ( !buf )
    {
        DEBUG("Out-of-mem\n");
        return -1;
    }

    memcpy(buf, p->data, p->datalen);

    *dest = buf;
    *len = p->varlen;

    return 0;
}

static void store_variable(entry_t *p, void *val, size_t len)
{
    TRACE();
    if ( !p || !val )
        return;

    TRACE();
    if ( p->data )
        free(p->data);

    TRACE();
    p->datalen = len;
    p->data = malloc(p->datalen);
    memcpy(p->data, val, p->datalen);
    TRACE();
}

static void new_variable(entry_t *p, void *varname, size_t varlen, void *val, size_t len)
{
    TRACE();
    if ( !p || !val || !varname )
        return;

    TRACE();
    if ( p->var )
        free(p->var);

    TRACE();
    if ( p->data )
        free(p->data);

    TRACE();

    p->varlen = varlen;
    p->var = malloc(p->varlen);
    memcpy(p->var, varname, p->varlen);
    TRACE();

    p->datalen = len;
    p->data = malloc(p->datalen);
    memcpy(p->data, val, p->datalen);
    TRACE();
}

int db_set(void *varname, size_t varlen, void *val, size_t len)
{
    int i;
    entry_t *p;

    if ( !varname )
        return -1;

    TRACE();
    for ( i=0; i<ENTRY_LEN; i++ )
    {
        p = &db[i];
        if ( memcmp(p->var, (void*)varname, p->varlen) )
            break;
    }
    TRACE();

    /* If this var already exists, replace the data */
    if ( i != ENTRY_LEN )
    {
        store_variable(p, val, len);
        return 0;
    }
    TRACE();

    /* Find a free slot and fill it with the new variable */
    for ( i=0; i<ENTRY_LEN; i++ )
    {
        p = &db[i];
        if ( p->var == NULL || p->data == NULL )
        {
            new_variable(p, varname, varlen, val, len);
            break;
        }
    }
    TRACE();

    /* There are no free entry slots */
    if ( i == ENTRY_LEN )
    {
        return -1;
    }
    TRACE();

    return 0;
}

int db_save(void)
{
#if 0
    size_t len;
    int ret, fd;

    fd = open(DBPATH, O_RDWR | O_CREAT);
    if ( fd < 0 )
        return -1;

    string = (db);
    if ( !string )
        return -1;

    len = strlen(string);
    ret = write(fd, (void *)string, sizeof(db));
    if ( ret !=  len )
    {
        return -1;
    }
#endif
    return -1;
}
