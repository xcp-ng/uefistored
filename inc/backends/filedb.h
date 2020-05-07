#ifndef __H_VARSTOREDMEM_
#define __H_VARSTOREDMEM_

#include <stdint.h>

int filedb_init(const char *dbpath,
                const char *varlenpath,
                const char *attrspath);
void filedb_deinit(void);
int filedb_get(void *, size_t, void** , size_t *, uint32_t*);
int filedb_set(void *, size_t, void *, size_t, uint32_t);

#endif
