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

int xapi_nvram_serialize(serializable_var_t *vars, size_t len, void *data, size_t size)
{
    serializable_var_t *var;
    size_t current_size = 0;
    size_t i;
    void *p;

    for ( i=0; i<len; i++ )
    {
        if ( current_size + vars[i].data_len + vars[i].variable_len + 
             sizeof(vars[i].data_len) + sizeof(vars[i].variable_len) > size )
             return -1;

        var = &vars[i];
        p = data + current_size;
        memcpy(p, &var->variable_len, sizeof(var->variable_len));
        current_size += sizeof(var->variable_len);

        p = data + current_size;
        memcpy(p, var->variable, var->variable_len);
        current_size += var->variable_len;

        p = data + current_size;
        memcpy(p, &var->data_len, sizeof(var->data_len));
        current_size += sizeof(var->data_len);

        p = data + current_size;
        memcpy(p, var->data, var->data_len);
        current_size += var->data_len;
    }

    return 0;
}
