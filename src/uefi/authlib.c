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
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

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

struct auth_data {
    int len;
    uint8_t *data;
};

static struct auth_data pk_auth_data;

/*
 * Global database array for scratch
 */
uint32_t setup_mode;

static EFI_GUID signature_support[] = {
    EFI_CERT_SHA1_GUID,
    EFI_CERT_SHA256_GUID,
    EFI_CERT_RSA2048_GUID,
    EFI_CERT_X509_GUID
};

/*
 * Hash context pointer
 */
SHA256_CTX *hash_ctx = NULL;

static int load_auth(const char *fpath, struct auth_data *auth)
{
    struct stat statbuf;
    int fd, ret;

    if (!fpath || !auth)
        return -1;

    ret = stat(fpath, &statbuf);

    if (ret < 0) {
        ERROR("failed to stat %s\n", fpath);
        return ret;
    }

    fd = open(fpath, O_RDONLY);

    if (fd < 0) {
        ERROR("failed to open %s\n", fpath);
        return fd;
    }

    auth->data = malloc(statbuf.st_size);

    if (!auth->data) {
        ERROR("out of memory\n");
        return -1;
    }

    auth->len = read(fd, auth->data, statbuf.st_size);

    close(fd);

    return auth->len;
}

int auth_lib_load(const char *pk_auth_file)
{
    if (!pk_auth_file)
        return -1;

    if (load_auth(pk_auth_file, &pk_auth_data) < 0) {
        ERROR("error opening file %s\n", pk_auth_file);
        return -1;
    }

    return 0;
}

/**
 * Initialization for authenticated variable services.
 * 
 * @return EFI_SUCCESS if initialize is successful, otherwise an EFI errno
 */
EFI_STATUS
auth_lib_initialize(void)
{
    EFI_STATUS status = EFI_SUCCESS;
    uint8_t secure_boot = 0;
    uint8_t DeployedMode = 0;
    uint8_t AuditMode = 0;

    setup_mode = SETUP_MODE;

    status = storage_set(EFI_SIGNATURE_SUPPORT_NAME, &gEfiGlobalVariableGuid,
                         signature_support, sizeof(signature_support),
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                 EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    status = storage_set(L"SetupMode", &gEfiGlobalVariableGuid, &setup_mode,
                         sizeof(setup_mode), EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    status = auth_lib_process_variable(L"PK", &gEfiGlobalVariableGuid,
                pk_auth_data.data, pk_auth_data.len,
                EFI_VARIABLE_NON_VOLATILE |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
                EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        ERROR("Failed to set PK, status=%s (0x%02lx)\n",
                efi_status_str(status), status);
        return EFI_DEVICE_ERROR;
    }

    status = storage_set(L"AuditMode", &gEfiGlobalVariableGuid, &AuditMode,
                         sizeof(AuditMode), EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    status = storage_set(L"DeployedMode", &gEfiGlobalVariableGuid, &DeployedMode,
                         sizeof(DeployedMode), EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    status = storage_set(L"SecureBoot", &gEfiGlobalVariableGuid, &secure_boot,
                         sizeof(secure_boot), EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    hash_ctx = malloc(sizeof(SHA256_CTX));

    if (!hash_ctx) {
        return EFI_DEVICE_ERROR;
    }

    return status;
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
auth_lib_process_variable(UTF16 *variable_name, EFI_GUID *vendor_guid,
                               void *data, uint64_t data_size,
                               uint32_t attributes)
{
  EFI_STATUS status;

  if (compare_guid(vendor_guid, &gEfiGlobalVariableGuid) && (strcmp16(variable_name, EFI_PLATFORM_KEY_NAME) == 0)){
    status = process_var_with_pk(variable_name, vendor_guid, data, data_size, attributes, true);
  } else if (compare_guid(vendor_guid, &gEfiGlobalVariableGuid) && (strcmp16(variable_name, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) {
    status = process_var_with_pk(variable_name, vendor_guid, data, data_size, attributes, false);
  } else if (compare_guid(vendor_guid, &gEfiImageSecurityDatabaseGuid) &&
             ((strcmp16(variable_name, EFI_IMAGE_SECURITY_DATABASE)  == 0) ||
              (strcmp16(variable_name, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
              (strcmp16(variable_name, EFI_IMAGE_SECURITY_DATABASE2) == 0))) {

        status = process_var_with_pk(variable_name, vendor_guid, data, data_size, attributes, false);
        if (status != EFI_SUCCESS) {
            status = process_var_with_kek(variable_name, vendor_guid, data, data_size, attributes);
        }
  } else {
    status = process_variable(variable_name, vendor_guid, data, data_size, attributes);
  }

  return status;
}
