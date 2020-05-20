#include "xapi_nvram.h"

size_t xapi_nvram_serialized_size(serializable_var_t *vars, size_t len)
{
    size_t size = 0;
    size_t i;
    
    for ( i=0; i<len; i++ )
        size += vars[i].variable_len + sizeof(vars[i].variable_len) +
                vars[i].data_len + sizeof(vars[i].data_len);

    return size;
}
