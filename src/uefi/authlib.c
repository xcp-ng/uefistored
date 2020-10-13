/** @file
  Implement authentication services for the authenticated variables.

  Caution: This module requires additional review when modified.
  This driver will have external input - variable data. It may be input in SMM mode.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.
  Variable attribute should also be checked to avoid authentication bypass.
     The whole SMM authentication variable design relies on the integrity of flash part and SMM.
  which is assumed to be protected by platform.  All variable code and metadata in flash/SMM Memory
  may not be modified without authorization. If platform fails to protect these resources,
  the authentication service provided in this driver will be broken, and the behavior is undefined.

Copyright (c) 2015 - 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <limits.h>
#include <stdint.h>

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

static uint8_t default_pk[] = {
#include "default_pk.txt"
};

///
/// Global database array for scratch
///
uint32_t setup_mode;

static EFI_GUID SignatureSupport[] = { EFI_CERT_SHA1_GUID, EFI_CERT_SHA256_GUID,
                                EFI_CERT_RSA2048_GUID, EFI_CERT_X509_GUID };

//
// Hash context pointer
//
SHA256_CTX *hash_ctx = NULL;

/**
  Initialization for authenticated varibale services.
  If this initialization returns error status, other APIs will not work
  and expect to be not called then.

  @retval EFI_SUCCESS               Function successfully executed.
  @retval EFI_OUT_OF_RESOURCES      Fail to allocate enough resource.
  @retval EFI_UNSUPPORTED           Unsupported to process authenticated variable.

**/
EFI_STATUS
auth_lib_initialize(void)
{
    EFI_STATUS status = EFI_SUCCESS;
    void *data;
    size_t data_size;
    uint8_t setup_mode = 0;
    uint8_t secure_boot = 0;
    uint8_t DeployedMode = 0;
    uint8_t AuditMode = 0;

    status = storage_set(EFI_SIGNATURE_SUPPORT_NAME, &gEfiGlobalVariableGuid,
                         SignatureSupport, sizeof(SignatureSupport),
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                 EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    }

    status = auth_lib_process_variable(L"PK", &gEfiGlobalVariableGuid,
                default_pk, sizeof(default_pk),
                EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
        ERROR("Failed to set PK\n");
    }

    status = auth_internal_find_variable(L"PK",
                                         &gEfiGlobalVariableGuid,
                                         (void **)&data, &data_size);

    if (status != EFI_NOT_FOUND && status != EFI_SUCCESS) {
        return EFI_DEVICE_ERROR;
    } else if (status == EFI_NOT_FOUND) {
        setup_mode = 1;
    } else {
        // TODO: allow enabling secureboot
        //secure_boot = 1;
    }


    status = storage_set(L"SetupMode", &gEfiGlobalVariableGuid, &setup_mode,
                         sizeof(setup_mode), EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS);

    if (status != EFI_SUCCESS) {
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

    DDEBUG("setup_mode is %x\n", setup_mode);
    DDEBUG("secure_boot is %x\n", secure_boot);

    hash_ctx = malloc(sizeof(SHA256_CTX));

    if (!hash_ctx) {
        return EFI_DEVICE_ERROR;
    }

    return status;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set.

  @param[in] VariableName           Name of the variable.
  @param[in] VendorGuid             Variable vendor GUID.
  @param[in] Data                   Data pointer.
  @param[in] DataSize               Size of Data.
  @param[in] Attributes             Attribute value of the variable.

  @retval EFI_SUCCESS               The firmware has successfully stored the variable and its data as
                                    defined by the Attributes.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.
  @retval EFI_SECURITY_VIOLATION    The variable is with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACESS
                                    set, but the AuthInfo does NOT pass the validation
                                    check carried out by the firmware.
  @retval EFI_UNSUPPORTED           Unsupported to process authenticated variable.

**/
EFI_STATUS
auth_lib_process_variable(UTF16 *VariableName, EFI_GUID *VendorGuid,
                               void *Data, uint64_t DataSize,
                               uint32_t Attributes)
{
  EFI_STATUS status = EFI_SUCCESS;

  if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (strcmp16 (VariableName, EFI_PLATFORM_KEY_NAME) == 0)){
    status = process_var_with_pk(VariableName, VendorGuid, Data, DataSize, Attributes, true);
  } else if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (strcmp16 (VariableName, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) {
    DDEBUG("process_var_with_pk()\n");
    // status = process_var_with_pk(VariableName, VendorGuid, Data, DataSize, Attributes, FALSE);
  } else if (CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
             ((strcmp16 (VariableName, EFI_IMAGE_SECURITY_DATABASE)  == 0) ||
              (strcmp16 (VariableName, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
              (strcmp16 (VariableName, EFI_IMAGE_SECURITY_DATABASE2) == 0))) {
        DDEBUG("process_var_with_pk()\n");
        DDEBUG("ProcessVarWithKek()\n");
        //status = process_var_with_pk(VariableName, VendorGuid, Data, DataSize, Attributes, FALSE);
        if (EFI_ERROR (status)) {
            // status = ProcessVarWithKek (VariableName, VendorGuid, Data, DataSize, Attributes);
        }
  } else {
    DDEBUG("process_variable\n");
    status = process_variable(VariableName, VendorGuid, Data, DataSize, Attributes);
  }

  return status;
}
