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
#include "uefi/image_authentication.h"
#include "uefi/types.h"

///
/// Global database array for scratch
///
uint8_t    *mCertDbStore;
uint8_t    mVendorKeyState;
uint32_t   mMaxCertDbSize;
uint32_t   mPlatformMode;

EFI_GUID mSignatureSupport[] = {EFI_CERT_SHA1_GUID, EFI_CERT_SHA256_GUID, EFI_CERT_RSA2048_GUID, EFI_CERT_X509_GUID};


#define VAR_CHECK_VARIABLE_PROPERTY_REVISION      0x0001
//
// 1. Set by VariableLock PROTOCOL
// 2. Set by VarCheck PROTOCOL
//
// If set, other fields for check will be ignored.
//
#define VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY     (1)

typedef struct {
  uint16_t                            Revision;
  uint16_t                            Property;
  uint32_t                            Attributes;
  uint64_t                             MinSize;
  uint64_t                             MaxSize;
} VAR_CHECK_VARIABLE_PROPERTY;

typedef struct {
  EFI_GUID                      *Guid;
  UTF16                        *Name;
  VAR_CHECK_VARIABLE_PROPERTY   VariableProperty;
} VARIABLE_ENTRY_PROPERTY;

//
// Hash context pointer
//
SHA256_CTX  *mHashCtx = NULL;

VARIABLE_ENTRY_PROPERTY mAuthVarEntry[] = {
  {
    &gEfiSecureBootEnableDisableGuid,
    EFI_SECURE_BOOT_ENABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS,
      sizeof (uint8_t),
      sizeof (uint8_t)
    }
  },
  {
    &gEfiCustomModeEnableGuid,
    EFI_CUSTOM_MODE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS,
      sizeof (uint8_t),
      sizeof (uint8_t)
    }
  },
  {
    &gEfiVendorKeysNvGuid,
    EFI_VENDOR_KEYS_NV_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      sizeof (uint8_t),
      sizeof (uint8_t)
    }
  },
  {
    &gEfiCertDbGuid,
    EFI_CERT_DB_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      sizeof (uint32_t),
      LONG_MAX
    }
  },
  {
    &gEfiCertDbGuid,
    EFI_CERT_DB_VOLATILE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT_AT,
      sizeof (uint32_t),
      LONG_MAX
    }
  },
};

void **mAuthVarAddressPointer[9];

/**
  Initialization for authenticated varibale services.
  If this initialization returns error status, other APIs will not work
  and expect to be not called then.

  @retval EFI_SUCCESS               Function successfully executed.
  @retval EFI_OUT_OF_RESOURCES      Fail to allocate enough resource.
  @retval EFI_UNSUPPORTED           Unsupported to process authenticated variable.

**/
EFI_STATUS
AuthVariableLibInitialize (void)
{
  EFI_STATUS            Status;
  uint32_t                VarAttr;
  uint8_t                 *Data;
  uint64_t                 DataSize;
  uint8_t                 SecureBootMode;
  uint8_t                 SecureBootEnable;
  uint8_t                 CustomMode;
  uint32_t                ListSize;

  //
  // Reserve runtime buffer for certificate database. The size excludes variable header and name size.
  // Use EFI_CERT_DB_VOLATILE_NAME size since it is longer.
  //
  mMaxCertDbSize = (uint32_t) (MAX_VARIABLE_DATA_SIZE + MAX_VARIABLE_NAME_SIZE - sizeof (EFI_CERT_DB_VOLATILE_NAME));
  mCertDbStore   = malloc(mMaxCertDbSize);
  if (mCertDbStore == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = auth_internal_find_variable (EFI_PLATFORM_KEY_NAME, &gEfiGlobalVariableGuid, (void **) &Data, &DataSize);
  if (EFI_ERROR (Status)) {
    DEBUG("Variable 'PK' does not exist\n");
  } else {
    DEBUG("Variable 'PK'  exists\n");
  }

  //
  // Create "SetupMode" variable with BS+RT attribute set.
  //
  if (EFI_ERROR (Status)) {
    mPlatformMode = SETUP_MODE;
  } else {
    mPlatformMode = USER_MODE;
  }
  Status = storage_set(
             EFI_SETUP_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &mPlatformMode,
             sizeof(uint8_t),
             EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Create "SignatureSupport" variable with BS+RT attribute set.
  //
  Status  = storage_set (
              EFI_SIGNATURE_SUPPORT_NAME,
              &gEfiGlobalVariableGuid,
              mSignatureSupport,
              sizeof(mSignatureSupport),
              EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
              );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // If "SecureBootEnable" variable exists, then update "SecureBoot" variable.
  // If "SecureBootEnable" variable is SECURE_BOOT_ENABLE and in USER_MODE, Set "SecureBoot" variable to SECURE_BOOT_MODE_ENABLE.
  // If "SecureBootEnable" variable is SECURE_BOOT_DISABLE, Set "SecureBoot" variable to SECURE_BOOT_MODE_DISABLE.
  //
  SecureBootEnable = SECURE_BOOT_DISABLE;
  Status =auth_internal_find_variable (EFI_SECURE_BOOT_ENABLE_NAME, &gEfiSecureBootEnableDisableGuid, (void **) &Data, &DataSize);
  if (!EFI_ERROR (Status)) {
    if (mPlatformMode == USER_MODE){
      SecureBootEnable = *(uint8_t *) Data;
    }
  } else if (mPlatformMode == USER_MODE) {
    //
    // "SecureBootEnable" not exist, initialize it in USER_MODE.
    //
    SecureBootEnable = SECURE_BOOT_ENABLE;
    Status = storage_set (
               EFI_SECURE_BOOT_ENABLE_NAME,
               &gEfiSecureBootEnableDisableGuid,
               &SecureBootEnable,
               sizeof (uint8_t),
               EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Create "SecureBoot" variable with BS+RT attribute set.
  //
  if (SecureBootEnable == SECURE_BOOT_ENABLE && mPlatformMode == USER_MODE) {
    SecureBootMode = SECURE_BOOT_MODE_ENABLE;
  } else {
    SecureBootMode = SECURE_BOOT_MODE_DISABLE;
  }
  Status = storage_set (
             EFI_SECURE_BOOT_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &SecureBootMode,
             sizeof (uint8_t),
             EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

#if 0
  DEBUG ("Variable %s is %x\n", EFI_SETUP_MODE_NAME, mPlatformMode));
  DEBUG ("Variable %s is %x\n", EFI_SECURE_BOOT_MODE_NAME, SecureBootMode));
  DEBUG ("Variable %s is %x\n", EFI_SECURE_BOOT_ENABLE_NAME, SecureBootEnable));
#endif

  //
  // Initialize "CustomMode" in STANDARD_SECURE_BOOT_MODE state.
  //
  CustomMode = STANDARD_SECURE_BOOT_MODE;
  Status = storage_set (
             EFI_CUSTOM_MODE_NAME,
             &gEfiCustomModeEnableGuid,
             &CustomMode,
             sizeof (uint8_t),
             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Check "certdb" variable's existence.
  // If it doesn't exist, then create a new one with
  // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set.
  //
  Status =auth_internal_find_variable (
             EFI_CERT_DB_NAME,
             &gEfiCertDbGuid,
             (void **) &Data,
             &DataSize
             );
  if (EFI_ERROR (Status)) {
    VarAttr  = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    ListSize = sizeof (uint32_t);
    Status   = storage_set (
                 EFI_CERT_DB_NAME,
                 &gEfiCertDbGuid,
                 &ListSize,
                 sizeof (uint32_t),
                 VarAttr
                 );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else {
    //
    // Clean up Certs to make certDB & Time based auth variable consistent
    //
    Status = CleanCertsFromDb();
    if (EFI_ERROR (Status)) {
      DEBUG ("Clean up CertDB fail! Status %lx\n", Status);
      return Status;
    }
  }

  //
  // Create "certdbv" variable with RT+BS+AT set.
  //
  VarAttr  = EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  ListSize = sizeof (uint32_t);
  Status   = storage_set (
               EFI_CERT_DB_VOLATILE_NAME,
               &gEfiCertDbGuid,
               &ListSize,
               sizeof (uint32_t),
               VarAttr
               );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Check "VendorKeysNv" variable's existence and create "VendorKeys" variable accordingly.
  //
  Status = auth_internal_find_variable (EFI_VENDOR_KEYS_NV_VARIABLE_NAME, &gEfiVendorKeysNvGuid, (void **) &Data, &DataSize);
  if (!EFI_ERROR (Status)) {
    mVendorKeyState = *(uint8_t *)Data;
  } else {
    //
    // "VendorKeysNv" not exist, initialize it in VENDOR_KEYS_VALID state.
    //
    mVendorKeyState = VENDOR_KEYS_VALID;
    Status = storage_set (
               EFI_VENDOR_KEYS_NV_VARIABLE_NAME,
               &gEfiVendorKeysNvGuid,
               &mVendorKeyState,
               sizeof (uint8_t),
               EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Create "VendorKeys" variable with BS+RT attribute set.
  //
  Status = storage_set (
             EFI_VENDOR_KEYS_VARIABLE_NAME,
             &gEfiGlobalVariableGuid,
             &mVendorKeyState,
             sizeof (uint8_t),
             EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DEBUG ("Variablel ");
  dprint_name((UTF16*)EFI_VENDOR_KEYS_VARIABLE_NAME, strsize16((UTF16*)EFI_VENDOR_KEYS_VARIABLE_NAME));
  DPRINTF(" is %x\n", mVendorKeyState);

#if 0
  AuthVarLibContextOut->StructVersion = AUTH_VAR_LIB_CONTEXT_OUT_STRUCT_VERSION;
  AuthVarLibContextOut->StructSize = sizeof (AUTH_VAR_LIB_CONTEXT_OUT);
  AuthVarLibContextOut->AuthVarEntry = mAuthVarEntry;
  AuthVarLibContextOut->AuthVarEntryCount = ARRAY_SIZE (mAuthVarEntry);
  mAuthVarAddressPointer[0] = (void **) &mCertDbStore;
  mAuthVarAddressPointer[1] = (void **) &mHashCtx;
  mAuthVarAddressPointer[2] = (void **) &mAuthVarLibContextIn;
  mAuthVarAddressPointer[3] = (void **) &(mAuthVarLibContextIn->FindVariable),
  mAuthVarAddressPointer[4] = (void **) &(mAuthVarLibContextIn->FindNextVariable),
  mAuthVarAddressPointer[5] = (void **) &(mAuthVarLibContextIn->UpdateVariable),
  mAuthVarAddressPointer[6] = (void **) &(mAuthVarLibContextIn->GetScratchBuffer),
  mAuthVarAddressPointer[7] = (void **) &(mAuthVarLibContextIn->CheckRemainingSpaceForConsistency),
  mAuthVarAddressPointer[8] = (void **) &(mAuthVarLibContextIn->AtRuntime),
  AuthVarLibContextOut->AddressPointer = mAuthVarAddressPointer;
  AuthVarLibContextOut->AddressPointerCount = ARRAY_SIZE (mAuthVarAddressPointer);
#endif

  return Status;
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
AuthVariableLibProcessVariable (
 UTF16         *VariableName,
 EFI_GUID       *VendorGuid,
 void           *Data,
 uint64_t          DataSize,
 uint32_t         Attributes
  )
{
  EFI_STATUS        Status;

#if 0
  if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_PLATFORM_KEY_NAME) == 0)){
    Status = ProcessVarWithPk (VariableName, VendorGuid, Data, DataSize, Attributes, TRUE);
  } else if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) {
    Status = ProcessVarWithPk (VariableName, VendorGuid, Data, DataSize, Attributes, FALSE);
  } else if (CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
             ((StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE)  == 0) ||
              (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
              (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE2) == 0)
             )) {
    Status = ProcessVarWithPk (VariableName, VendorGuid, Data, DataSize, Attributes, FALSE);
    if (EFI_ERROR (Status)) {
      Status = ProcessVarWithKek (VariableName, VendorGuid, Data, DataSize, Attributes);
    }
  } else {
#endif
    Status = process_variable (VariableName, VendorGuid, Data, DataSize, Attributes);
#if 0
  }
#endif

  return Status;
}
