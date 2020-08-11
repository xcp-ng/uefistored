#include <stdlib.h>
#include <stdint.h>

#include "storage.h"
#include "test_common.h"
#include "common.h"

static int fuzz_set(const uint8_t *dp, size_t size)
{
    int ret;
    UTF16 *name;
    void *data;
    uint32_t attrs;
    const uint8_t *p;

    if ( size % 2 != 0 || size < 4 )
        return -1;

    p = dp;
    name = malloc(size);

    if ( !name )
        return -1;

    memcpy(name, dp, size);
    name[(size/2)-1] = '\0';

    data = malloc(size);

    if ( !data )
        return -1;

    memcpy(data, dp, size);

    if ( size >= sizeof(uint32_t) )
    {
        memcpy(&attrs, dp, sizeof(attrs));
    }
    else
    {
        attrs = (uint32_t)dp[0];
    }

    ret = storage_set(name, data, size, attrs);

cleanup:
    free(data);
    free(name);

    return ret;
}

static int reset = 1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int ret;

    if ( !data )
       return 0;

    if ( reset )
    {
        storage_init();
        reset = 0;
    }

    ret = fuzz_set(data, size);
    
    if ( ret == -2 )
        reset = 1;

    return 0; 
}

