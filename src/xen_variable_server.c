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
#include "variables_service.h"
#include "xen_variable_server.h"
#include "xapi.h"

extern bool efi_at_runtime;

/* Request for GET_NEXT_VARIABLE or GET_VARIABLE */
struct get_request {
    uint32_t version;
    command_t command;
    uint64_t buffer_size;
    uint64_t namesz;
    uint8_t name[MAX_VARIABLE_NAME_SIZE];
    EFI_GUID guid;
};


FILE *input_snapshot_fd;
FILE *output_snapshot_fd;

#if 1
FILE *test_log = NULL;

#define MYLOG(...)  				            \
	do {					                    \
        if (test_log) {                         \
            fprintf(test_log, __VA_ARGS__); 	\
            fflush(test_log);			        \
        }                                       \
	} while (0)
#else
#define MYLOG(...) do { } while( 0 )
#endif

#if 0
static void save_shmem_page(void *comm_buf, FILE *fd)
{
    fwrite(comm_buf, 1, 4096, fd);
    fflush(fd);
}
#endif

static void serialize_buffer_too_small(void *comm_buf, size_t required_size)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)required_size);
}

static struct get_request *unserialize_get_request(void *comm_buf)
{
    struct get_request *request;
    const uint8_t *ptr;

    if (!comm_buf)
        return NULL;

    request = calloc(1, sizeof(struct get_request));

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
static int serialize_get_error(variable_t *var, struct get_request *request, void *comm_buf)
{
    int ret;
    uint8_t *ptr = comm_buf;

    assert(request != NULL);
    assert(comm_buf != NULL);

    ret = 0;

    if (!var || (efi_at_runtime && !(var->attrs & EFI_VARIABLE_RUNTIME_ACCESS))) {
        /*
         * The variable was not found or the system is at runtime and the
         * variable is not accessible at runtime.
         *
         * Return to the guest EFI_NOT_FOUND.
         */
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
    struct get_request *request;
    variable_t *var;

    request = unserialize_get_request(comm_buf);

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

    var = storage_find_variable((UTF16*)request->name, &request->guid);

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
    EFI_STATUS status;
    uint8_t *ptr;
    uint64_t max_variable_storage;
    uint64_t remaining_variable_storage;
    uint64_t max_variable_size;
    const uint8_t *inptr = comm_buf;

    ptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if (version != UEFISTORED_VERSION) {
        ERROR("Bad uefistored version: %u\n", version);
        status = EFI_UNSUPPORTED;
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    command = unserialize_uint32(&inptr);

    if (command != COMMAND_QUERY_VARIABLE_INFO) {
        ERROR("Bad command: %u\n", command);
        status = EFI_DEVICE_ERROR;
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    attrs = unserialize_uint32(&inptr);

    status = query_variable_info(attrs, &max_variable_storage,
                                 &remaining_variable_storage,
                                 &max_variable_size);
    ;

    if (status != EFI_SUCCESS) {
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    ptr = comm_buf;
    serialize_result(&ptr, status);
    serialize_value(&ptr, max_variable_storage);
    serialize_value(&ptr, remaining_variable_storage);
    serialize_value(&ptr, max_variable_size);
}

static void handle_set_variable(void *comm_buf)
{
    uint8_t *ptr;
    const uint8_t *inptr = comm_buf;
    EFI_GUID guid;
    int namesz;
    int datasz;
    UTF16 *name;
    uint8_t data[MAX_VARIABLE_DATA_SIZE] = { 0 };
    void *dp = data;
    uint32_t attrs, command, version;
    EFI_STATUS status;

    ptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if (version != UEFISTORED_VERSION) {
        ERROR("Invalid XenVariable OVMF module version number: %d, only supports version 1\n",
              version);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    command = unserialize_uint32(&inptr);

    if (command != COMMAND_SET_VARIABLE) {
        ERROR("BUG: uefistored accidentally passed a non SET_VARIABLE buffer to the"
              "%s function!, returning EFI_DEVICE_ERROR\n",
              __func__);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    namesz = unserialize_namesz(&inptr);

    if (namesz == 0) {
        DDEBUG("status=%s\n", efi_status_str(EFI_INVALID_PARAMETER));
        ptr = comm_buf;
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    if (namesz > MAX_VARIABLE_NAME_SIZE) {
        DDEBUG("status=%s\n", efi_status_str(EFI_OUT_OF_RESOURCES));
        ptr = comm_buf;
        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
        return;
    }

    name = malloc(namesz + sizeof(UTF16));
    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, inptr), name,
                     namesz + sizeof(UTF16));
    unserialize_guid(&inptr, &guid);

    datasz = unserialize_data(&inptr, dp, MAX_VARIABLE_DATA_SIZE);

    if (datasz < 0) {
        ptr = comm_buf;
        DDEBUG("status=%s (0x%02lx)\n",
                efi_status_str(EFI_OUT_OF_RESOURCES), EFI_OUT_OF_RESOURCES);
        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
        free(name);
        return;
    }

    attrs = unserialize_uint32(&inptr);

    /* Let XenVariable inform us if OVMF has exited Boot Services */
    set_efi_runtime(unserialize_boolean(&inptr));

#if 0
    if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINTN") == 0)
    {
        DDEBUG("XV_DEBUG_UINTN: 0x%lx\n",  *((uint64_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINT32") == 0)
    {
        DDEBUG("XV_DEBUG_UINT32: 0x%x\n",  *((uint32_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINT64") == 0)
    {
        DDEBUG("XV_DEBUG_UINT64: 0x%lx\n",  *((uint64_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINT8") == 0)
    {
        DDEBUG("XV_DEBUG_UINT8: 0x%x\n",  *((uint8_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_STR") == 0)
    {
        char stringbuf[512];
        uc2_ascii_safe((UTF16*)data, datasz, stringbuf, 512);
        DDEBUG("XV_DEBUG_STR: %s\n", stringbuf);
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_ASCII") == 0)
    {
        DDEBUG("XV_DEBUG_ASCII: %s\n", (char*)data);
        free(name);
        return;
    }
#endif

    status = set_variable(name, &guid, attrs, (size_t)datasz, dp);
    ptr = comm_buf;
    serialize_result(&ptr, status);

    free(name);
}

struct get_request *unserialize_get_next_request(void *comm_buf)
{
    const uint8_t *ptr;
    struct get_request *request;

    if (!comm_buf)
        return NULL;

    request = calloc(1, sizeof(struct get_request));

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
    const variable_t *next;

    struct get_request *request;

    request = unserialize_get_next_request(comm_buf);

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
    } else if (request->buffer_size < next->namesz) {
        /* Return to guest EFI_BUFFER_TOO_SMALL */
        serialize_buffer_too_small(ptr, next->namesz + sizeof(UTF16));
    } else {
        /* Return to guest EFI_SUCCESS */
        serialize_result(&ptr, EFI_SUCCESS);
        serialize_name(&ptr, next->name);
        serialize_guid(&ptr, &next->guid);
    }

err:
    free(request);
}

static void log_guid(EFI_GUID *guid)
{
    int i;

    if (!guid) {
        MYLOG("[]");
        return;
    }

    MYLOG("[");
    for (i=0; i<sizeof(*guid); i++) {
        MYLOG("0x%02x", ((uint8_t*)guid)[i]);
        if (i < sizeof(*guid) - 1) {
            MYLOG(", ");
        }
    }
    MYLOG("]");
}

static void log_get(void *comm_buf)
{
    const uint8_t *ptr = comm_buf;
    uint8_t name[MAX_VARIABLE_NAME_SIZE];
    EFI_GUID guid;
    int name_len, data_len;
    bool at_runtime;
    uint64_t i;

    (void)ptr;
    (void)name;
    (void)guid;
    (void)name_len;
    (void)data_len;
    (void)at_runtime;
    (void)i;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_uint32(&ptr);

    MYLOG("Request: GET<");

    name_len = unserialize_namesz(&ptr);
    unserialize_name(&ptr, BUFFER_REMAINING(comm_buf, ptr), name, name_len + sizeof(UTF16));
    if (name_len < 0) {
        MYLOG(">\n");
        return;
    }
    unserialize_guid(&ptr, &guid);
    data_len = unserialize_uintn(&ptr);
    at_runtime = unserialize_boolean(&ptr);

    MYLOG("name=");
    for (i=0; i<name_len; i++) {
        if (isprint(name[i])) {
            MYLOG("%c", name[i]);
        }
    }
    MYLOG(", guid=");
    log_guid(&guid);
    MYLOG(", data_len=%lu, at_runtime=%s>\n", (size_t)data_len, at_runtime ? "true" : "false");
}

static void log_data(uint8_t *data, uint64_t data_len)
{
    uint64_t i;

    (void)data;
    (void)data_len;

    if (!data)
        return;

    if (data_len == 0)
        return;

    MYLOG("[");
    for (i=0; i<data_len; i++) {
	MYLOG("0x%02x", data[i]);

	if (i != data_len - 1) {
	    MYLOG(", ");
	}
    }
    MYLOG("]");
}

static void log_name(uint8_t *name, uint64_t name_len)
{
    uint64_t i;

    for (i=0; i<name_len; i++) {
        if (isprint(name[i])) {
            MYLOG("%c", name[i]);
        }
    }
}

static void log_set(const void *comm_buf)
{
    const uint8_t *ptr;
    uint8_t name[MAX_VARIABLE_NAME_SIZE];
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    int name_len;
    int data_len;
    EFI_GUID guid;
    uint32_t attr;
    bool at_runtime;

    (void)ptr;
    (void)name;
    (void)data;
    (void)name_len;
    (void)data_len;
    (void)guid;
    (void)attr;
    (void)at_runtime;

    ptr = comm_buf;
    unserialize_uint32(&ptr); /* version */
    unserialize_uint32(&ptr);

    MYLOG("Request: SET<");

    name_len = unserialize_data(&ptr, name, MAX_VARIABLE_NAME_SIZE);

    if (name_len < 0) {
        MYLOG(">\n");
        return;
    }

    unserialize_guid(&ptr, &guid);

    MYLOG("name=");
    log_name(name, name_len);

    MYLOG(", guid=");
    log_guid(&guid);

    data_len = unserialize_data(&ptr, data, MAX_VARIABLE_DATA_SIZE);

    if (data_len < 0) {
        MYLOG(">\n");
        return;
    }

    MYLOG(", data=");
    log_data(data, data_len);
    attr = unserialize_uint32(&ptr);
    at_runtime = unserialize_boolean(&ptr);
    MYLOG(", attr=0x%02x, at_runtime=%s>\n", attr, at_runtime ? "true" : "false");
}

static void log_result(const void *comm_buf, uint32_t command)
{
    uint32_t attrs;
    uint8_t data[MAX_VARIABLE_DATA_SIZE] = {0};
    uint64_t data_len = 0; 
    const uint8_t *ptr = comm_buf;
    uint64_t result;
    uint8_t name[MAX_VARIABLE_NAME_SIZE] = {0};
    EFI_GUID guid;

    (void) attrs;
    (void) data;
    (void) data_len;
    (void) result;
    (void) ptr;

    switch (command) {
    case COMMAND_GET_VARIABLE:
    {
        result = unserialize_uintn(&ptr);
        MYLOG("Response: GET<result=%s (0x%02lx)", efi_status_str(result), result);

        if (result == EFI_SUCCESS) {
            attrs = unserialize_uint32(&ptr);
            data_len = unserialize_data(&ptr, data, MAX_VARIABLE_DATA_SIZE);

            MYLOG(", attrs=0x%02x, data_len=%lu, data=", attrs, data_len);

            log_data(data, data_len);
            MYLOG(">\n");
        } else if (result == EFI_BUFFER_TOO_SMALL) {
            MYLOG(", required_size=%lu>\n", unserialize_uintn(&ptr));
        } else {
            MYLOG(">\n");
        }
        break;
    }

    case COMMAND_SET_VARIABLE:
    {
        result = unserialize_uintn(&ptr);
        MYLOG("Response: SET<result=%s (0x%02lx)>\n", efi_status_str(result), result);
        break;
    }

    case COMMAND_GET_NEXT_VARIABLE:
    {
        result = unserialize_uintn(&ptr);

        if (result == EFI_SUCCESS) {
            uint64_t name_len = unserialize_data(&ptr, name, MAX_VARIABLE_DATA_SIZE);
            unserialize_guid(&ptr, &guid);

            MYLOG("Response: GET_NEXT<result=%s (0x%02lx)",
                    efi_status_str(result), result);

            MYLOG(", guid=");
            log_guid(&guid);

            MYLOG("name=");
            log_name(name, name_len);
            MYLOG(">\n");
        } else if (result == EFI_BUFFER_TOO_SMALL) {
            uint64_t required_size;

            required_size = unserialize_uintn(&ptr);

            MYLOG("Response: GET_NEXT<result=%s (0x%02lx), required_size=%lu>\n",
                    efi_status_str(result), result, required_size);
        } else {
            MYLOG("Response: GET_NEXT<result=%s (0x%02lx)\n",
                    efi_status_str(result), result);
        }
        break;
    }

    default:
    	MYLOG("unimplemented: 0x%02x\n", command);
	break;
    }

}


void xen_variable_server_handle_request(void *comm_buf)
{
    const uint8_t *inptr = comm_buf;
    uint32_t command;

    if (!comm_buf) {
        ERROR("comm buffer is null!\n");
        return;
    }

    /* advance the pointer passed the version field */
    unserialize_uint32(&inptr);

    command = unserialize_uint32(&inptr);

    DDEBUG("command=0x%x\n", command);

    switch (command) {
    case COMMAND_GET_VARIABLE:
        log_get(comm_buf);
        handle_get_variable(comm_buf);
        break;
    case COMMAND_SET_VARIABLE:
        log_set(comm_buf);
        handle_set_variable(comm_buf);
        break;
    case COMMAND_GET_NEXT_VARIABLE:
        MYLOG("Request: GET_NEXT<>\n");
        handle_get_next_variable(comm_buf);
        break;
    case COMMAND_QUERY_VARIABLE_INFO:
        MYLOG("Request: QUERY_VARIABLE_INFO<>\n");
        handle_query_variable_info(comm_buf);
        break;
    case COMMAND_NOTIFY_SB_FAILURE:
        MYLOG("Request: COMMAND_NOTIFY_SB_FAILURE<>\n");
        /* fall through */
    default:
        ERROR("cmd: unknown, 0x%x\n", command);
        break;
    }

    log_result(comm_buf, command);
    MYLOG("\n");
}
