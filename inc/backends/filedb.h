#ifndef __H_VARSTOREDMEM_
#define __H_VARSTOREDMEM_

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/**
 * This is a super simple backend for varstored.  It simply uses
 * a file-backed key-value store to maintain UEFI variables.
 *
 * Two DBs are used.  One maps the variable name to the variable value.
 * The other maps the variable name to the variable value len.
 * This is required because KISSDB only accepts fixed-length keys and values.
 */

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DEFAULT_DBPATH "/var/run/xen/varstored-db.dat"
#define DEFAULT_DBPATH_VAR_LEN "/var/run/xen/varstored-db-var-len.dat"
#define DEFAULT_DBPATH_VAR_ATTRS "/var/run/xen/varstored-db-var-attrs.dat"

#define ENTRY_LEN 1024
#define FILEDB_KEY_SIZE 128 
#define FILEDB_VAL_SIZE 1024
#define FILEDB_VAR_ATTRS_VAL_SIZE (sizeof(uint32_t))

typedef struct {
    char name[FILEDB_KEY_SIZE];
} filedb_name_iter_t;

int filedb_init(const char *dbpath,
                const char *varlenpath,
                const char *attrspath);
void filedb_deinit(void);
int filedb_get(void *, size_t, void** , size_t *, uint32_t*);
int filedb_set(void *, size_t, void *, size_t, uint32_t);
void filedb_destroy(void);

void filedb_name_iter_init(void);
int filedb_name_iter_next(filedb_name_iter_t *p);
bool filedb_name_iter_initialized(void);
void filedb_name_iter_deinit(void);

#endif
