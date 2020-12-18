/**
 * Implement authentication services for the authenticated variables.
 *
 * Inspired by and modified from edk2, with the license:
 *
 * Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
 * This program and the accompanying materials
 * are licensed and made available under the terms and conditions of the BSD License
 * which accompanies this distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php
 * 
 * THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 * 
 */
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "common.h"
#include "log.h"
#include "storage.h"
#include "uefi/auth.h"
#include "uefi/authlib.h"
#include "uefi/auth_var_format.h"
#include "uefi/global_variable.h"
#include "uefi/guids.h"
#include "uefi/image_authentication.h"
#include "uefi/types.h"
#include "uefi/utils.h"

extern EFI_GUID gEfiGlobalVariableGuid;
extern bool secure_boot_enabled;

uint8_t setup_mode;

static EFI_GUID signature_support[] = { EFI_CERT_SHA1_GUID,
                                        EFI_CERT_SHA256_GUID,
                                        EFI_CERT_RSA2048_GUID,
                                        EFI_CERT_X509_GUID };

/*
 * Hash context pointer
 */
SHA256_CTX *hash_ctx = NULL;

static int load_auth(struct auth_data *auth)
{
    struct stat statbuf;
    int fd, ret;

    if (!auth || !auth->path)
        return -1;

    ret = stat(auth->path, &statbuf);

    if (ret < 0) {
        ERROR("failed to stat %s\n", auth->path);
        return ret;
    }

    fd = open(auth->path, O_RDONLY);

    if (fd < 0) {
        ERROR("failed to open %s\n", auth->path);
        return fd;
    }

    auth->var.datasz = statbuf.st_size;

    assert(auth->var.datasz < MAX_VARIABLE_DATA_SIZE);

    if (read(fd, auth->var.data, auth->var.datasz) < 0) {
        ERROR("failed to read %s\n", auth->path);
        ret = -1;
    }

    close(fd);

    return ret;
}

void auth_lib_load(struct auth_data *auths, size_t n)
{
    size_t i;

    if (!auths)
        return;

    for (i = 0; i < n; i++) {
        if (load_auth(&auths[i]) < 0) {
            ERROR("error opening file %s\n", auths[i].path);
        }
    }
}

static void load_auth_files(struct auth_data *auths, size_t n)
{
    size_t i;
    EFI_STATUS status;
    variable_t *var;

    for (i = 0; i < n; i++) {
        var = &auths[i].var;

        if (!storage_exists(var->name, var->namesz, &var->guid) && var->datasz > 0) {
            status = auth_lib_process_variable(var->name, var->namesz,
                                               &var->guid, var->data,
                                               var->datasz, var->attrs);

            if (status != EFI_SUCCESS) {
                DDEBUG("Failed to set SB variable from %s (attrs=0x%02x), status=%s (0x%02lx)\n",
                       auths[i].path, var->attrs, efi_status_str(status), status);
            } else {
                INFO("Successfuly set SB variable from %s (attrs=0x%02x)\n",
                       auths[i].path, var->attrs);
		dprint_variable(var);
	    }
        }
    }
}

/**
 * Initialization for authenticated variable services.
 * 
 * @return EFI_SUCCESS if initialize is successful, otherwise an EFI errno
 */
EFI_STATUS
auth_lib_initialize(struct auth_data *auths, size_t n)
{
    EFI_STATUS status = EFI_SUCCESS;
    uint8_t secure_boot = 0;
    uint8_t audit_mode = 0;

    hash_ctx = malloc(sizeof(SHA256_CTX));

    status = storage_set(L"SignatureSupport", sizeof_wchar(L"SignatureSupport"),
                         &gEfiGlobalVariableGuid, signature_support,
                         sizeof(signature_support),
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                 EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS)
        return status;

    if (storage_exists(L"PK", sizeof_wchar(L"PK"), &gEfiGlobalVariableGuid)) {
        status = update_platform_mode(USER_MODE);
    } else {
        status = update_platform_mode(SETUP_MODE);
    }

    if (status != EFI_SUCCESS)
        return status;

    load_auth_files(auths, n);

    secure_boot = secure_boot_enabled;

    status = storage_set(
            L"SecureBoot", sizeof_wchar(L"SecureBoot"), &gEfiGlobalVariableGuid,
            &secure_boot, sizeof(secure_boot),
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS)
        return status;

    return storage_set(
            L"AuditMode", sizeof_wchar(L"AuditMode"), &gEfiGlobalVariableGuid,
            &audit_mode, sizeof(audit_mode),
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
}

/**
 * Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set.
 *
 * @parm variable_name           Name of the variable.
 * @parm vendor_guid             Variable vendor GUID.
 * @parm data                   data pointer.
 * @parm data_size               Size of data.
 * @parm attributes             Attribute value of the variable.
 *
 * @return EFI_SUCCESS if variable is successfully stored, otherwise an EFI error code
 */
EFI_STATUS
auth_lib_process_variable(UTF16 *variable_name, size_t namesz,
                          EFI_GUID *vendor_guid, void *data, uint64_t data_size,
                          uint32_t attributes)
{
    EFI_STATUS status;

    if (compare_guid(vendor_guid, &gEfiGlobalVariableGuid) &&
        (strcmp16(variable_name, EFI_PLATFORM_KEY_NAME) == 0)) {
        status = process_var_with_pk(variable_name, namesz, vendor_guid, data,
                                     data_size, attributes, true);
    } else if (compare_guid(vendor_guid, &gEfiGlobalVariableGuid) &&
               (strcmp16(variable_name, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) {
        status = process_var_with_pk(variable_name, namesz, vendor_guid, data,
                                     data_size, attributes, false);
    } else if (compare_guid(vendor_guid, &gEfiImageSecurityDatabaseGuid) &&
               ((strcmp16(variable_name, EFI_IMAGE_SECURITY_DATABASE) == 0) ||
                (strcmp16(variable_name, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
                (strcmp16(variable_name, EFI_IMAGE_SECURITY_DATABASE2) == 0))) {
        status = process_var_with_pk(variable_name, namesz, vendor_guid, data,
                                     data_size, attributes, false);
        if (status != EFI_SUCCESS) {
            status = process_var_with_kek(variable_name, namesz, vendor_guid, data,
                                          data_size, attributes);
        }
    } else {
        status = process_variable(variable_name, namesz, vendor_guid, data, data_size,
                                  attributes);
    }

    return status;
}
