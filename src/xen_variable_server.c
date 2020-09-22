#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

#include "storage.h"
#include "common.h"
#include "info.h"
#include "log.h"
#include "serializer.h"
#include "uefi/types.h"
#include "uefi/guids.h"
#include "varnames.h"
#include "variables_service.h"
#include "xen_variable_server.h"
#include "xapi.h"

/*
 * Saving test input stores commands from the guest to be reused in testing.
 * Only for development!
 *
 * If 1, test input is saved to /uefistored.input.data. If 0, no op.
 */
#define SAVE_TEST_INPUT 0

static void buffer_too_small(void *comm_buf, size_t required_size)
{
    uint8_t *ptr = comm_buf;

    serialize_result(&ptr, EFI_BUFFER_TOO_SMALL);
    serialize_uintn(&ptr, (uint64_t)required_size);
}

static void handle_get_variable(void *comm_buf)
{
    int namesz;
    EFI_GUID guid;
    uint32_t attrs, version;
    uint64_t buflen;
    uint8_t data[MAX_VARIABLE_DATA_SIZE];
    UTF16 *name;
    EFI_STATUS status;
    uint8_t *ptr = comm_buf;
    const uint8_t *inptr = comm_buf;

    inptr = comm_buf;
    version = unserialize_uint32(&inptr);

    if (version != UEFISTORED_VERSION) {
        ERROR("Unsupported version of XenVariable RPC protocol\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if (unserialize_uint32(&inptr) != COMMAND_GET_VARIABLE) {
        ERROR("BUG in uefistored, wrong command\n");
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    namesz = unserialize_namesz(&inptr);

    if (namesz <= 0) {
        ptr = comm_buf;
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    name = malloc(namesz + sizeof(UTF16));

    if (!name) {
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    if (namesz > MAX_VARIABLE_NAME_SIZE) {
        free(name);
        ptr = comm_buf;
        serialize_result(&ptr, EFI_DEVICE_ERROR);
        return;
    }

    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, ptr), name,
                     namesz + sizeof(UTF16));
    unserialize_guid(&inptr, &guid);

    buflen = unserialize_uint64(&inptr);

    DEBUG("buflen=%lu\n", buflen);

    /* Let XenVariable inform us if OVMF has exited Boot Services */
    set_efi_runtime(unserialize_boolean(&inptr));

    status = get_variable(name, &guid, &attrs, &buflen, data);

    if (status == EFI_BUFFER_TOO_SMALL) {
        free(name);
        buffer_too_small(comm_buf, buflen);
        return;
    } else if (status) {
        free(name);
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_uint32(&ptr, attrs);
    serialize_data(&ptr, data, buflen);

    free(name);
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
        DEBUG("status=%s\n", efi_status_str(EFI_INVALID_PARAMETER));
        ptr = comm_buf;
        serialize_result(&ptr, EFI_INVALID_PARAMETER);
        return;
    }

    if (namesz > MAX_VARIABLE_NAME_SIZE) {
        DEBUG("status=%s\n", efi_status_str(EFI_OUT_OF_RESOURCES));
        ptr = comm_buf;
        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
        return;
    }

    name = malloc(namesz + sizeof(UTF16));
    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, inptr), name,
                     namesz + sizeof(UTF16));
    unserialize_guid(&inptr, &guid);

    datasz = unserialize_data(&inptr, dp, MAX_VARIABLE_DATA_SIZE);

    DEBUG("datasz=%d\n", datasz);

    if (datasz < 0) {
        ptr = comm_buf;
        DEBUG("status=%s (0x%02lx)\n",
                efi_status_str(EFI_OUT_OF_RESOURCES), EFI_OUT_OF_RESOURCES);
        serialize_result(&ptr, EFI_OUT_OF_RESOURCES);
        free(name);
        return;
    }

    attrs = unserialize_uint32(&inptr);

    /* Let XenVariable inform us if OVMF has exited Boot Services */
    set_efi_runtime(unserialize_boolean(&inptr));

#if 1
    if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINTN") == 0)
    {
        DEBUG("XV_DEBUG_UINTN: 0x%lx\n",  *((uint64_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINT32") == 0)
    {
        DEBUG("XV_DEBUG_UINT32: 0x%x\n",  *((uint32_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINT64") == 0)
    {
        DEBUG("XV_DEBUG_UINT64: 0x%lx\n",  *((uint64_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_UINT8") == 0)
    {
        DEBUG("XV_DEBUG_UINT8: 0x%x\n",  *((uint8_t*)data));
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_STR") == 0)
    {
        char stringbuf[512];
        uc2_ascii_safe((UTF16*)data, datasz, stringbuf, 512);
        DEBUG("XV_DEBUG_STR: %s\n", stringbuf);
        free(name);
        return;
    }
    else if (strcmp16(name, (UTF16*) L"XV_DEBUG_ASCII") == 0)
    {
        DEBUG("XV_DEBUG_ASCII: %s\n", (char*)data);
        free(name);
        return;
    }
#endif

    status = set_variable(name, &guid, attrs, (size_t)datasz, dp);
    ptr = comm_buf;
    serialize_result(&ptr, status);

    free(name);
}

static EFI_STATUS unserialize_get_next_variable(const void *comm_buf,
                                                uint64_t *namesz,
                                                UTF16 **name,
                                                uint64_t *guest_bufsz,
                                                EFI_GUID *guid)
{
    uint32_t command;
    const uint8_t *inptr = comm_buf;
    uint32_t version;

    if (!comm_buf || !namesz || !name || !guid)
        return EFI_DEVICE_ERROR;

    version = unserialize_uint32(&inptr);

    if (version != UEFISTORED_VERSION)
        WARNING("OVMF appears to be running an unsupported version of the XenVariable module\n");

    command = unserialize_uint32(&inptr);

    assert(command == COMMAND_GET_NEXT_VARIABLE);

    *guest_bufsz = unserialize_uintn(&inptr);
    *namesz = unserialize_namesz(&inptr) + sizeof(UTF16);

    if (*namesz > MAX_VARIABLE_NAME_SIZE)
        return EFI_INVALID_PARAMETER;

    *name = malloc(*namesz);

    if (!*name)
        return EFI_DEVICE_ERROR;

    unserialize_name(&inptr, BUFFER_REMAINING(comm_buf, inptr), *name, *namesz);
    unserialize_guid(&inptr, guid);

    /* Let XenVariable inform us if OVMF has exited Boot Services */
    set_efi_runtime(unserialize_boolean(&inptr));

    /*
     * Because name is the input and output buffer, it is sometimes
     * populated with guest_bufsz bytes and sometimes namesz bytes.
     * So we just allocated enough for either case.
     */
    if (*guest_bufsz > *namesz)
        *name = realloc(*name, *guest_bufsz);

    return EFI_SUCCESS;
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
    const uint8_t *inptr = comm_buf;
    uint64_t guest_bufsz = 0;
    uint64_t namesz = 0;
    UTF16 *name = NULL;
    EFI_GUID guid;
    EFI_STATUS status;

    status = unserialize_get_next_variable(inptr, &namesz, &name, &guest_bufsz,
                                           &guid);
    if (status) {
#if 1
        DPRINTF("%s:%u: ", __func__, __LINE__);
        if (!status) {
            dprint_name(name, namesz);
        }
        DPRINTF(": status=%s (0x%lx), namesz=%lu, guest_bufsz=%lu\n", 
                efi_status_str(status), status, namesz, guest_bufsz);
#endif
        ptr = comm_buf;
        serialize_result(&ptr, status);
        return;
    }

    DPRINTF("%s:%u: Current=", __func__, __LINE__);
    dprint_name(name, namesz);
    DPRINTF(", ");

    status = storage_next(&guest_bufsz, name, &guid);

#if 1
    if (!status) {
        DPRINTF("Next=");
        dprint_name(name, guest_bufsz);
        DPRINTF(", ");
    }
    DPRINTF(" status=%s (0x%lx), namesz=%lu, guest_bufsz=%lu\n", 
            efi_status_str(status), status, namesz, guest_bufsz);
#endif

    if (status == EFI_NOT_FOUND || status == EFI_DEVICE_ERROR) {
        serialize_result(&ptr, status);
        goto cleanup2;
    } else if (status == EFI_BUFFER_TOO_SMALL) {
        DPRINTF("BUFF TOO SMALL\n");
        dprint_name(name, namesz);
        DPRINTF("required bufsz=%lu\n", guest_bufsz);
        buffer_too_small(comm_buf, guest_bufsz);
        goto cleanup2;
    }


    assert(status == EFI_SUCCESS);

    ptr = comm_buf;
    serialize_result(&ptr, EFI_SUCCESS);
    serialize_name(&ptr, name);
    serialize_guid(&ptr, &guid);

cleanup2:
    free(name);
}

/**
 * Save the OVMF buffer to disk.
 *
 * This function is only used during development.
 * The saved buffer can be used as unit test input.
 *
 * @parm comm_buf The OVMF XenVariable buffer
 */
static void save_test_input(void *comm_buf)
{
    (void)comm_buf;

#if SAVE_TEST_INPUT
    FILE *fd;

    fd = fopen("uefistored.input.dat", "a+");

    if (!fd) {
        DEBUG("failed to open uestored.input.data, %s\n", strerror(errno));
        return;
    }

    fwrite(comm_buf, 1, 4096, fd);
    fclose(fd);
#endif
}

void xen_variable_server_handle_request(void *comm_buf)
{
    const uint8_t *inptr = comm_buf;
    uint32_t command;

    if (!comm_buf) {
        ERROR("comm buffer is null!\n");
        return;
    }

    save_test_input(comm_buf);

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
        /* fall through */
    default:
        ERROR("cmd: unknown\n");
        break;
    }
}
