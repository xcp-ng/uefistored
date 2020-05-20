#ifndef __H_XAPI_NVRAM_
#define __H_XAPI_NVRAM_

#include "common.h"

size_t xapi_nvram_serialized_size(serializable_var_t *vars, size_t);
int xapi_nvram_serialize(serializable_var_t *vars, size_t len, void *data, size_t size);

#endif // __H_XAPI_NVRAM_
