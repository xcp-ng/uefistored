#ifndef __H_VARSTOREDMEM_
#define __H_VARSTOREDMEM_

int db_init(void);
void db_deinit(void);
int db_get(void *, size_t, void** , size_t *);
int db_set(void *, size_t, void *, size_t);

#endif
