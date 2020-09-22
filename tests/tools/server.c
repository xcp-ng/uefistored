#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#include "log.h"
#include "storage.h"
#include "serializer.h"
#include "test_common.h"
#include "uefi/types.h"
#include "xen_variable_server.h"
#include "variables_service.h"

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static void pre_test(void)
{
    storage_init();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

static void post_test(void)
{
    storage_deinit();
    storage_destroy();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

int main(void)
{
    int fd;

    char buffer[SHMEM_PAGES * PAGE_SIZE];
        
    for (;;) {
        memset(buffer, 0 , SHMEM_PAGES * PAGE_SIZE);
        if (fread(buffer, 1, 4096, stdin) != 4096) {
            return -1;
        }

        xen_variable_server_handle_request(buffer);
    }

    return 0;
}
