#include <stdlib.h>
#include <stdint.h>

#include "storage.h"
#include "test_common.h"
#include "common.h"
#include "uefi/types.h"

static unsigned long iterations = 0;

static void get_next_all(void)
{
    EFI_STATUS status;
    UTF16 next[MAX_VARIABLE_NAME_SIZE] = { 0 };
    EFI_GUID next_guid;
    size_t next_sz = MAX_VARIABLE_NAME_SIZE;
    size_t i, count;

    count = storage_count();

    for (i=0; i<count + 1; i++) {
        next_sz = MAX_VARIABLE_NAME_SIZE;
        storage_next(&next_sz, next, &next_guid);
    }
}

static uint8_t *prev_data;
static size_t prev_size;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    EFI_GUID guid;
    int ret;
    uint32_t attrs;
    uint8_t buf[MAX_VARIABLE_DATA_SIZE];
    size_t buf_len;
    uint32_t buf_attrs;
    EFI_STATUS status;
    uint8_t *new;

    if (!data || size < sizeof(uint64_t) || size % 2 != 0)
        return 0;

    new = malloc(size);
    memcpy(new, data, size);
    memset(new + size - 2, 0, sizeof(UTF16));

    switch (new[0] & 0xf) {
    case COMMAND_GET_VARIABLE:
        storage_get((UTF16*)prev_data, &guid, buf, MAX_VARIABLE_DATA_SIZE, &buf_len, &buf_attrs);
        break;
    case COMMAND_SET_VARIABLE:
    {
        memcpy(&attrs, &new[1], sizeof(uint32_t));
        attrs &= (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS);

        status = storage_set((UTF16*)new, &guid, new, size, attrs);
        if (status == EFI_SUCCESS) {
            if (prev_data)
                free(prev_data);

            prev_data = malloc(size);
            memcpy(prev_data, new, size);
            prev_size = size;
        }
            
        break;
    }
    case COMMAND_GET_NEXT_VARIABLE:
        get_next_all();
        break;
    default:
        break;
    }

    if (iterations >= 5000) {
        iterations = 0;
        storage_destroy();
    } else {
        iterations++;
    }

    free(new);

    return 0;
}
