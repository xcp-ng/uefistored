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
#include "xapi.h"

bool efi_at_runtime = false;

struct request {
    uint32_t version;
    command_t command;
    int namesz;
    uint8_t name[MAX_VARIABLE_NAME_SIZE];
    int buffer_size;
    uint8_t buffer[MAX_VARIABLE_DATA_SIZE];
    EFI_GUID guid;
    uint32_t attrs;
};

#if DEBUG
static void debug_request(struct request *req)
{
    if (!req)
        return;

    DPRINTF("request: version=%u, command=0x%02x, name=", req->version, req->command);
    dprint_name((UTF16*)req->name, req->namesz);
    DPRINTF(", ");

    if (req->command == COMMAND_SET_VARIABLE)
        dprint_data(req->buffer, req->buffer_size);

    DPRINTF(", guid=0x%02llx", *((unsigned long long*)&req->guid));

    if (req->command == COMMAND_SET_VARIABLE)
        DPRINTF(", attrs=0x%02x, ", req->attrs);

    DPRINTF("\n");
}
#else
#define debug_request(...) do { } while ( 0 )
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
    else if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) && \
             (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS))
        return EFI_SECURITY_VIOLATION;
    /* We do not support EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS */
    else if (attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
        return EFI_SECURITY_VIOLATION;
    else if (attrs & EFI_VARIABLE_APPEND_WRITE)
        DDEBUG("attrs & EFI_VARIABLE_APPEND_WRITE");

    return EFI_SUCCESS;
}

static void serialize_buffer_too_small(void *comm_buf, size_t required_size)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)required_size);
}

static struct request *unserialize_get_request(void *comm_buf)
{
    struct request *request;
    const uint8_t *ptr;

    if (!comm_buf)
        return NULL;

    request = calloc(1, sizeof(struct request));

    if (!request)
        return NULL;

    ptr = comm_buf;

    request->version = unserialize_uint32(&ptr);

    if (request->version != UEFISTORED_VERSION) {
        free(request);
        return NULL;
    }

    request->command = (command_t)unserialize_uint32(&ptr);
    request->namesz = unserialize_data(&ptr, request->name, MAX_VARIABLE_NAME_SIZE);

    if (request->namesz < 0) {
        free(request);
        return NULL;
    }
    
    unserialize_guid(&ptr, &request->guid);
    request->buffer_size = unserialize_uint64(&ptr);

    efi_at_runtime = unserialize_boolean(&ptr);

    return request;
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
static int serialize_get_error(variable_t *var, struct request *request, void *comm_buf)
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
    struct request *request;
    variable_t *var;

    request = unserialize_get_request(comm_buf);

    debug_request(request);

    ptr = comm_buf;

    if (!request) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if (request->command != COMMAND_GET_VARIABLE) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        goto done;
    }

    if (request->namesz <= 0) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto done;
    }

    var = storage_find_variable((UTF16*)request->name, request->namesz, &request->guid);

    if (serialize_get_error(var, request, comm_buf) < 0)
        goto done;

    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint32(&ptr, var->attrs);
    serialize_data(&ptr, var->data, var->datasz);

done:
    free(request);
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

    if (attrs == 0 ||
            ((attrs & EFI_VARIABLE_RUNTIME_ACCESS) &&
             !(attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS))) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    max_variable_storage = MAX_STORAGE_SIZE;
    max_variable_size = MAX_VARIABLE_SIZE;
    remaining_variable_storage = MAX_STORAGE_SIZE - storage_used();

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_value(&ptr, max_variable_storage);
    serialize_value(&ptr, remaining_variable_storage);
    serialize_value(&ptr, max_variable_size);
}

static struct request *unserialize_set_request(void *comm_buf)
{
    struct request *request;
    const uint8_t *ptr;

    if (!comm_buf)
        return NULL;

    request = calloc(1, sizeof(struct request));

    if (!request)
        return NULL;

    ptr = comm_buf;

    request->version = unserialize_uint32(&ptr);

    if (request->version != UEFISTORED_VERSION) {
        free(request);
        return NULL;
    }

    request->command = (command_t)unserialize_uint32(&ptr);
    request->namesz = unserialize_data(&ptr, request->name, MAX_VARIABLE_NAME_SIZE);

    if (request->namesz < 0) {
        free(request);
        return NULL;
    }
    
    unserialize_guid(&ptr, &request->guid);
    request->buffer_size = unserialize_data(&ptr, request->buffer, MAX_VARIABLE_DATA_SIZE);
    request->attrs = unserialize_uint32(&ptr);

    efi_at_runtime = unserialize_boolean(&ptr);

    return request;
}

#define strcmp16_len(a, a_n, b) \
    (a_n == sizeof_wchar(b) && !strcmp16(a, b))

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
    struct request *request;
    EFI_STATUS status;

    request = unserialize_set_request(comm_buf);

    debug_request(request);

    if (!request) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Memory error\n");
        goto done;
    }

    if (request->version != 1) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Bad version: %u\n", request->version);
        goto done;
    }

    if (request->command != COMMAND_SET_VARIABLE) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Bad command: 0x%02x\n", request->command);
        goto done;
    }

    if (request->name[0] == 0 ||
            ((request->attrs & EFI_VARIABLE_RUNTIME_ACCESS) &&
             !(request->attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS))) {
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        goto done;
    }

    if (is_ro((UTF16*)request->name, request->namesz, &request->guid)) {
        serialize_result(&ptr, EFI_WRITE_PROTECTED);
        goto done;
    }

    status = evaluate_attrs(request->attrs);

    if (status != EFI_SUCCESS) {
        serialize_result(&ptr, status);
        goto done;
    }

    if (request->attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS ||
            is_secure_boot_variable((UTF16*)request->name, request->namesz, &request->guid)) {
        status = auth_lib_process_variable((UTF16*)request->name, request->namesz, &request->guid,
                                                request->buffer, request->buffer_size,
                                                request->attrs);

    } else {
        status = storage_set((UTF16*)request->name, request->namesz, &request->guid,
                             request->buffer, request->buffer_size,
                             request->attrs);
    }

    serialize_result(&ptr, status);

done:
    free(request);
}

struct request *unserialize_get_next_request(void *comm_buf)
{
    const uint8_t *ptr;
    struct request *request;

    if (!comm_buf)
        return NULL;

    request = calloc(1, sizeof(struct request));

    if (!request)
        return NULL;

    ptr = comm_buf;

    request->version = unserialize_uint32(&ptr);

    if (request->version != UEFISTORED_VERSION) {
        free(request);
        return NULL;
    }

    request->command = unserialize_uint32(&ptr);
    request->buffer_size = unserialize_uintn(&ptr);
    request->namesz = unserialize_data(&ptr, request->name, MAX_VARIABLE_NAME_SIZE);
    ((UTF16*)request->name)[request->namesz / 2] = 0;

    if (request->namesz < 0) {
        free(request);
        return NULL;
    }

    unserialize_guid(&ptr, &request->guid);

    efi_at_runtime = unserialize_boolean(&ptr);

    return request;
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
    variable_t *next;
    struct request *request;

    request = unserialize_get_next_request(comm_buf);

    debug_request(request);

    ptr = comm_buf;

    if (!request) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Memory error\n");
        goto err;
    }

    if (request->version != 1) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Bad version: %u\n", request->version);
        goto err;
    }

    if (request->command != COMMAND_GET_NEXT_VARIABLE) {
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        ERROR("Bad command: 0x%02x\n", request->command);
        goto err;
    }

    next = storage_next_variable((UTF16*)request->name, &request->guid);

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

err:
    free(request);
}

void xen_variable_server_handle_request(void *comm_buf)
{
    const uint8_t *inptr = comm_buf;
    uint8_t *outptr = comm_buf;
    uint32_t command;

    if (!comm_buf) {
        ERROR("comm buffer is null!\n");
        return;
    }

    /* advance the pointer passed the version field */
    unserialize_uint32(&inptr);

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
        if (xapi_sb_notify() < 0) {
            DDEBUG("xapi_sb_notify() error\n");
            serialize_result(&outptr, EFI_DEVICE_ERROR);
        } else {
            DDEBUG("xapi_sb_notify() success\n");
            serialize_result(&outptr, EFI_SUCCESS);
        }
        break;
    default:
        ERROR("cmd: unknown, 0x%x\n", command);
        break;
    }

#if 0
    const uint8_t *dbg_ptr = comm_buf;
    DDEBUG("result: 0x%02lx\n", unserialize_result(&dbg_ptr));
#endif
}
