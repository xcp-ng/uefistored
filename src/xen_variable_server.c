#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include <ctype.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

#include "backend.h"
#include "common.h"
#include "info.h"
#include "log.h"
#include "serializer.h"
#include "storage.h"
#include "uefi/types.h"
#include "uefi/guids.h"
#include "varnames.h"
#include "xen_variable_server.h"
#include "uefi/authlib.h"
#include "uefi/utils.h"

bool efi_at_runtime = false;

struct request {
    uint32_t version;
    command_t command;
    int namesz;
    uint8_t name[MAX_VARIABLE_NAME_SIZE];
    ssize_t buffer_size;
    uint8_t buffer[MAX_VARIABLE_DATA_SIZE];
    EFI_GUID guid;
    uint32_t attrs;
};

#if DEBUG
static void debug_request(struct request *req)
{
    if (!req)
        return;

    DPRINTF("request: version=%u, command=0x%02x, name=", req->version,
            req->command);
    dprint_name((UTF16 *)req->name, req->namesz);
    DPRINTF(", ");

    if (req->command == COMMAND_SET_VARIABLE)
        dprint_data(req->buffer, req->buffer_size);

    DPRINTF(", guid=0x%02llx", *((unsigned long long *)&req->guid));

    if (req->command == COMMAND_SET_VARIABLE)
        DPRINTF(", attrs=0x%02x, ", req->attrs);

    DPRINTF("\n");
}
#else
#define debug_request(...)                                                     \
    do {                                                                       \
    } while (0)
#endif

EFI_STATUS evaluate_attrs(uint32_t attrs)
{
    /* No support for hardware error record */
    if (attrs & EFI_VARIABLE_HARDWARE_ERROR_RECORD)
        return EFI_UNSUPPORTED;
    /* If RT is set, BS must also be set */
    else if ((attrs & RT_BS_ATTRS) == EFI_VARIABLE_RUNTIME_ACCESS)
        return EFI_INVALID_PARAMETER;
    /* Not both authentication bits may be set */
    else if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) &&
             (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS))
        return EFI_SECURITY_VIOLATION;
    /* We do not support EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS */
    else if (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
        return EFI_UNSUPPORTED;
    else if (attrs & EFI_VARIABLE_APPEND_WRITE)
        DBG("attrs & EFI_VARIABLE_APPEND_WRITE");

    return EFI_SUCCESS;
}

static void serialize_buffer_too_small(void *comm_buf, size_t required_size)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)required_size);
}

static EFI_STATUS unserialize_get_request(struct request *request, void *comm_buf)
{
    const uint8_t *ptr;

    if (!comm_buf || !request)
        return EFI_DEVICE_ERROR;

    ptr = comm_buf;

    request->version = unserialize_uint32(&ptr);

    if (request->version != UEFISTORED_VERSION) {
        return EFI_UNSUPPORTED;
    }

    request->command = (command_t)unserialize_uint32(&ptr);
    request->namesz =
            unserialize_data(&ptr, request->name, MAX_VARIABLE_NAME_SIZE);

    if (request->namesz < 0)
        return EFI_OUT_OF_RESOURCES;

    unserialize_guid(&ptr, &request->guid);
    request->buffer_size = unserialize_uint64(&ptr);
    efi_at_runtime = unserialize_boolean(&ptr);

    return EFI_SUCCESS;
}

/**
 * Serialize a GetVariable error.
 *
 * @parm var the variable struct of the requested variable
 * @parm request the request structure
 * @parm comm_buf the shared memory page with the guest
 *
 * @return 0 if no error found, otherwise -1.
 */
static int serialize_get_error(variable_t *var, struct request *request,
                               void *comm_buf)
{
    int ret;
    uint8_t *ptr = comm_buf;

    assert(request != NULL);
    assert(comm_buf != NULL);

    ret = 0;

    /*
     * The variable was not found or the system is at runtime and the
     * variable is not accessible at runtime.
     *
     * Return to the guest EFI_NOT_FOUND.
     */
    if (!var) {
        serialize_result(&ptr, EFI_NOT_FOUND);
        ret = -1;
    } else if (efi_at_runtime && !(var->attrs & EFI_VARIABLE_RUNTIME_ACCESS)) {
        serialize_result(&ptr, EFI_NOT_FOUND);
        ret = -1;
    } else if (request->buffer_size < var->datasz) {
        /*
         * The guest's buffer is not large enough, return EFI_BUFFER_TOO_SMALL.
         */
        serialize_buffer_too_small(ptr, var->datasz);
        ret = -1;
    }

    return ret;
}

static void handle_get_variable(void *comm_buf)
{
    uint8_t *ptr;
    struct request req = { 0 };
    struct request *request = &req;
    EFI_STATUS status;
    variable_t *var;

    ptr = comm_buf;

    status = unserialize_get_request(request, comm_buf);
    if (status != EFI_SUCCESS) {
        serialize_result(&ptr, status);
        return;
    }

    debug_request(request);

    if (request->command != COMMAND_GET_VARIABLE) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if (request->namesz <= 0) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    var = storage_find_variable((UTF16 *)request->name, request->namesz,
                                &request->guid);

    if (serialize_get_error(var, request, comm_buf) < 0)
        return;

    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint32(&ptr, var->attrs);
    serialize_data(&ptr, var->data, var->datasz);
}

static void handle_query_variable_info(void *comm_buf)
{
    uint32_t attrs, version, command;
    uint8_t *ptr;
    uint64_t max_variable_storage;
    uint64_t remaining_variable_storage;
    uint64_t max_variable_size;
    const uint8_t *inptr = comm_buf;

    ptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if (version != UEFISTORED_VERSION) {
        ERROR("Bad uefistored version: %u\n", version);
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    command = unserialize_uint32(&inptr);

    if (command != COMMAND_QUERY_VARIABLE_INFO) {
        ERROR("Bad command: %u\n", command);
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    attrs = unserialize_uint32(&inptr);

    if (attrs == 0 || ((attrs & EFI_VARIABLE_RUNTIME_ACCESS) &&
                       !(attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS))) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    max_variable_storage = MAX_STORAGE_SIZE;
    max_variable_size = MAX_VARIABLE_SIZE;
    remaining_variable_storage = MAX_STORAGE_SIZE - storage_used();

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint64(&ptr, max_variable_storage);
    serialize_uint64(&ptr, remaining_variable_storage);
    serialize_uint64(&ptr, max_variable_size);
}

static EFI_STATUS unserialize_set_request(struct request *request, void *comm_buf)
{
    const uint8_t *ptr;

    if (!comm_buf || !request)
        return EFI_DEVICE_ERROR;

    ptr = comm_buf;
    request->version = unserialize_uint32(&ptr);
    assert(request->version == UEFISTORED_VERSION);
    request->command = (command_t)unserialize_uint32(&ptr);
    request->namesz =
            unserialize_data(&ptr, request->name, MAX_VARIABLE_NAME_SIZE);

    if (request->namesz < 0)
        return EFI_OUT_OF_RESOURCES;

    unserialize_guid(&ptr, &request->guid);
    request->buffer_size =
            unserialize_data(&ptr, request->buffer, MAX_VARIABLE_DATA_SIZE);

    if (request->buffer_size < 0)
        return EFI_OUT_OF_RESOURCES;

    request->attrs = unserialize_uint32(&ptr);
    efi_at_runtime = unserialize_boolean(&ptr);

    return EFI_SUCCESS;
}

#define strcmp16_len(a, a_n, b) (a_n == sizeof_wchar(b) && !strcmp16(a, b))

/**
 * Returns true if variable is read-only, otherwise false.
 */
static bool is_ro(UTF16 *name, uint64_t namesz, EFI_GUID *guid)
{
    if (!name || !guid)
        return false;

    /* All of the read-only variables are global */
    if (!compare_guid(guid, &gEfiGlobalVariableGuid))
        return false;

    if (strcmp16_len(name, namesz, L"SecureBoot") ||
        strcmp16_len(name, namesz, L"SetupMode") ||
        strcmp16_len(name, namesz, L"AuditMode") ||
        strcmp16_len(name, namesz, L"DeployedMode") ||
        strcmp16_len(name, namesz, L"SignatureSupport"))
        return true;

    return false;
}

static void handle_set_variable(void *comm_buf)
{
    uint8_t *ptr = comm_buf;
    struct request req = { 0 };
    struct request *request = &req;
    EFI_STATUS status;

    status = unserialize_set_request(request, comm_buf);
    if (status != EFI_SUCCESS) {
        serialize_result(&ptr, status);
        return;
    };

    debug_request(request);

    if (request->command != COMMAND_SET_VARIABLE) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Bad command: 0x%02x\n", request->command);
        return;
    }

    if (request->name[0] == 0 ||
        ((request->attrs & EFI_VARIABLE_RUNTIME_ACCESS) &&
         !(request->attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS))) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    if (is_ro((UTF16 *)request->name, request->namesz, &request->guid)) {
        serialize_result(&ptr, EFI_WRITE_PROTECTED);
        return;
    }

    status = evaluate_attrs(request->attrs);

    if (status != EFI_SUCCESS) {
        serialize_result(&ptr, status);
        return;
    }

    if (request->attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS ||
        is_secure_boot_variable((UTF16 *)request->name, request->namesz,
                                &request->guid)) {
        status = auth_lib_process_variable(
                (UTF16 *)request->name, request->namesz, &request->guid,
                request->buffer, request->buffer_size, request->attrs);

    } else {
        status = storage_set((UTF16 *)request->name, request->namesz,
                             &request->guid, request->buffer,
                             request->buffer_size, request->attrs);
    }

    if (status == EFI_SUCCESS && request->attrs & EFI_VARIABLE_NON_VOLATILE) {
        backend_set();
    }

    serialize_result(&ptr, status);
}

static int unserialize_get_next_request(struct request *request, void *comm_buf)
{
    const uint8_t *ptr;

    if (!comm_buf || !request)
        return -1;

    ptr = comm_buf;
    request->version = unserialize_uint32(&ptr);

    assert(request->version == 1);

    request->command = unserialize_uint32(&ptr);
    request->buffer_size = unserialize_uintn(&ptr);
    request->namesz =
            unserialize_data(&ptr, request->name, MAX_VARIABLE_NAME_SIZE);

    if (request->namesz < 0)
        return -1;

    unserialize_guid(&ptr, &request->guid);
    efi_at_runtime = unserialize_boolean(&ptr);

    return 0;
}

/**
 * Return the names of current UEFI variables, one-by-one.
 *
 * This implements the UEFI Variable service GetNextVariableName()
 * function.
 *
 * @comm_buf:  The shared memory page with the OVMF XenVariable module.
 */
static void handle_get_next_variable(void *comm_buf)
{
    uint8_t *ptr = comm_buf;
    struct request req = { 0 };
    struct request *request = &req;
    variable_t *next;

    ptr = comm_buf;

    if (unserialize_get_next_request(request, comm_buf) < 0) {
        ERROR("failed to unserialize request\n");
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    assert(request->version == 1);
    assert(request->command == COMMAND_GET_NEXT_VARIABLE);

    debug_request(request);


    next = storage_next_variable((UTF16 *)request->name, request->namesz,
                                 &request->guid);

    ptr = comm_buf;

    if (!next) {
        /* Return to guest EFI_NOT_FOUND, no more variables left */
        serialize_result(&ptr, EFI_NOT_FOUND);
    } else if (request->buffer_size < next->namesz + 2) {
        /* Return to guest EFI_BUFFER_TOO_SMALL */
        serialize_buffer_too_small(ptr, next->namesz + 2);
    } else {
        /* Return to guest EFI_SUCCESS */
        serialize_result(&ptr, EFI_SUCCESS);
        serialize_name(&ptr, next->name, next->namesz);
        serialize_guid(&ptr, &next->guid);
    }
}

void xen_variable_server_handle_request(void *comm_buf)
{
    const uint8_t *inptr = comm_buf;
    uint8_t *outptr = comm_buf;
    uint32_t command;
    uint32_t version;

    if (!comm_buf) {
        ERROR("comm buffer is null!\n");
        return;
    }

    /* advance the pointer passed the version field */
    version = unserialize_uint32(&inptr);

    if (version != 1) {
        serialize_result(&outptr, EFI_DEVICE_ERROR);
        ERROR("Bad version: %u\n", version);
        return;
    }

    command = unserialize_uint32(&inptr);

    switch (command) {
    case COMMAND_GET_VARIABLE:
        handle_get_variable(comm_buf);
        break;
    case COMMAND_SET_VARIABLE:
        handle_set_variable(comm_buf);
        break;
    case COMMAND_GET_NEXT_VARIABLE:
        handle_get_next_variable(comm_buf);
        break;
    case COMMAND_QUERY_VARIABLE_INFO:
        handle_query_variable_info(comm_buf);
        break;
    case COMMAND_NOTIFY_SB_FAILURE:
        if (backend_notify() < 0) {
            serialize_result(&outptr, EFI_DEVICE_ERROR);
        } else {
            serialize_result(&outptr, EFI_SUCCESS);
        }
        break;
    default:
        ERROR("cmd: unknown, 0x%x\n", command);
        break;
    }
}
