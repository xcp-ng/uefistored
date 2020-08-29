#include <stdlib.h>
#include <stdint.h>

#include "common.h"
#include "test_common.h"
#include "storage.h"
#include "xen_variable_server.h"

static void fuzz_xen_variable_server(const uint8_t *data, size_t blocksz)
{
    void *p, *mem, *backup;
    uint32_t *command;
    size_t blocks, i, total, rem;

    if (!data)
        return;

    if (blocksz == 0)
        return;

    mem = malloc(SHMEM_SIZE);
    memset(mem, 0, SHMEM_SIZE);
    p = mem;
    total = 0;
    blocks = SHMEM_SIZE / blocksz;

    for (i = 0; i < blocks; i++) {
        memcpy(p, data, blocksz);
        p = (void *)(((uint64_t)p) + blocksz);
        total += blocksz;
    }

    rem = SHMEM_SIZE % (blocks * blocksz);
    if (rem > 0) {
        memcpy(p, data, rem);
        total += rem;
    }

    /* Turn into a valid command more often */
    command = mem;
    command[0] = command[0] % 2;
    command[1] = command[1] % 6;

    for (i = 0; i < MAX_VARIABLE_COUNT + 2; i++) {
        xen_variable_server_handle_request(mem);
    }

    free(mem);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data)
        return 0;

    storage_init();
    fuzz_xen_variable_server(data, size);
    storage_destroy();
    return 0;
}
