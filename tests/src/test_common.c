#include <wchar.h>
#include <stdbool.h>

#include "test_common.h"

#include "common.h"
#include "serializer.h"
#include "xen_variable_server.h"

static uint8_t comm_buf[SHMEM_SIZE];

#define EFI_AT_RUNTIME false

static inline void exec_command(void *p)
{
    xen_variable_server_handle_request(p);
}

EFI_STATUS testutil_set_variable(wchar_t *name, EFI_GUID *guid,
                                 uint32_t attr, size_t data_size, void *data)
{
    EFI_STATUS status;
    uint8_t *ptr;
    const uint8_t *outptr;

    ptr = comm_buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_command(&ptr, COMMAND_SET_VARIABLE);
    serialize_name(&ptr, name);
    serialize_guid(&ptr, guid);
    serialize_data(&ptr, data, data_size);
    serialize_uint32(&ptr, attr);
    serialize_boolean(&ptr, EFI_AT_RUNTIME);

    exec_command(comm_buf);

    outptr = comm_buf;
    status = unserialize_result(&outptr);

    memset(comm_buf, 0, sizeof(comm_buf));

    return status;
}

EFI_STATUS testutil_query_variable_info(uint32_t attr,
                                   uint64_t *maximum_variable_storage_size,
                                   uint64_t *remaining_variable_storage_size,
                                   uint64_t *maximum_variable_size)
{
    const uint8_t *outptr;
    uint8_t *ptr;
    EFI_STATUS status;

    ptr = comm_buf;
    serialize_uint32(&ptr, 1); /* version */
    serialize_command(&ptr, COMMAND_QUERY_VARIABLE_INFO);
    serialize_uint32(&ptr, attr);

    exec_command(comm_buf);

    outptr = comm_buf;
    status = unserialize_result(&outptr);

    switch (status)
    {
    case EFI_SUCCESS:
        *maximum_variable_storage_size = unserialize_uint64(&outptr);
        *remaining_variable_storage_size = unserialize_uint64(&outptr);
        *maximum_variable_size = unserialize_uint64(&outptr);
        break;
    default:
        break;
    }

    memset(comm_buf, 0, sizeof(comm_buf));

    return status;
}
