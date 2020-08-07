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

  ProcessVarWithPk(), ProcessVarWithKek() and ProcessVariable() are the function to do
  variable authentication.

  VerifyTimeBasedPayloadAndUpdate() and VerifyCounterBasedPayload() are sub function to do verification.
  They will do basic validation for authentication data structure, then call crypto library
  to verify the signature.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "auth_service.h"
#include "common.h"
#include "CryptRsaBasic.h"
#include "CryptX509.h"
#include "CryptSha256.h"
#include "uefitypes.h"
#include "varnames.h"
#include "uefi_guids.h"
#include "pkcs7_verify.h"
#include "ramdb.h"

void  *mHashCtx = NULL;

#define MAX_CERT_DB_SIZE (PAGE_SIZE*2)
uint8_t mCertDbStore[MAX_CERT_DB_SIZE];
const uint32_t mMaxCertDbSize = MAX_CERT_DB_SIZE;
EFI_GUID mSignatureSupport[] = {EFI_CERT_SHA1_GUID, EFI_CERT_SHA256_GUID, EFI_CERT_RSA2048_GUID, EFI_CERT_X509_GUID};


uint32_t mPlatformMode;
uint32_t mVendorKeyState;

//
// Public Exponent of RSA Key.
//
const uint8_t mRsaE[] = { 0x01, 0x00, 0x01 };

const uint8_t mSha256OidValue[] = { 0x60, 0x86, 0x48, 0x01, 0x65,
				  0x03, 0x04, 0x02, 0x01 };

static void _show(const char *func, const char *string, void *data, size_t n)
{
    size_t i;
    uint16_t *p = data;

    printf("%s:%s", func, string);
    for ( i=0; i<n; i++ )
    {
        if ( i % 8 == 0 )
            printf("\n");
        printf("0x%04x ", p[i]);
    }
    printf("\n\n");
}

#define show(string, data, n) _show(__func__, string, data, n)

//
// Requirement for different signature type which have been defined in UEFI spec.
// These data are used to perform SignatureList format check while setting PK/KEK variable.
//
EFI_SIGNATURE_ITEM mSupportSigItem[] = {
	//{SigType,                       SigHeaderSize,   SigDataSize  }
	{ EFI_CERT_SHA256_GUID, 0, 32 },
	{ EFI_CERT_RSA2048_GUID, 0, 256 },
	{ EFI_CERT_RSA2048_SHA256_GUID, 0, 256 },
	{ EFI_CERT_SHA1_GUID, 0, 20 },
	{ EFI_CERT_RSA2048_SHA1_GUID, 0, 256 },
	{ EFI_CERT_X509_GUID, 0, ((uint32_t)~0) },
	{ EFI_CERT_SHA224_GUID, 0, 28 },
	{ EFI_CERT_SHA384_GUID, 0, 48 },
	{ EFI_CERT_SHA512_GUID, 0, 64 },
	{ EFI_CERT_X509_SHA256_GUID, 0, 48 },
	{ EFI_CERT_X509_SHA384_GUID, 0, 64 },
	{ EFI_CERT_X509_SHA512_GUID, 0, 80 }
};

EFI_TIME *to_timestamp(void *data, size_t sz)
{
    if ( sz < sizeof(EFI_VARIABLE_AUTHENTICATION_2) )
        return NULL;

    return &((EFI_VARIABLE_AUTHENTICATION_2 *)data)->TimeStamp;
}

/**
  Finds variable in storage blocks of volatile and non-volatile storage areas.

  This code finds variable in storage blocks of volatile and non-volatile storage areas.
  If VariableName is an empty string, then we just return the first
  qualified variable without comparing VariableName and VendorGuid.

  @param[in]  VariableName          Name of the variable to be found.
  @param[in]  VendorGuid            Variable vendor GUID to be found.
  @param[out] Data                  Pointer to data address.
  @param[out] DataSize              Pointer to data size.
  @param[out] attrs                 Pointer to attrs.

  @retval EFI_INVALID_PARAMETER     If VariableName is not an empty string,
                                    while VendorGuid is NULL.
  @retval EFI_SUCCESS               Variable successfully found.
  @retval EFI_NOT_FOUND             Variable not found

**/
EFI_STATUS
AuthServiceInternalFindVariable(UTF16 *VariableName,
				const EFI_GUID *VendorGuid, void **Data,
				uint64_t *DataSize, 
                uint32_t *attrs)
{
    size_t len;
    int ret;
    uint32_t tmpattrs;
    uint8_t data[MAX_VARDATA_SZ];

    if ( !VariableName || !VendorGuid )
        return EFI_DEVICE_ERROR;

    ret = ramdb_get(VariableName, data, MAX_VARDATA_SZ, &len, &tmpattrs);

    if ( ret == VAR_NOT_FOUND )
        return EFI_NOT_FOUND;
    else if ( ret < 0 )
        return EFI_DEVICE_ERROR;

    if ( Data )
    {
        *Data = malloc(len);
        memcpy(*Data, data, len);
        if ( DataSize )
            *DataSize = len;
    }

    if ( attrs )
        *attrs = tmpattrs;

    return EFI_SUCCESS;
}

/**
  Find matching signer's certificates for common authenticated variable
  by corresponding VariableName and VendorGuid from "certdb" or "certdbv".

  The data format of "certdb" or "certdbv":
  //
  //     uint32_t CertDbListSize;
  // /// AUTH_CERT_DB_DATA Certs1[];
  // /// AUTH_CERT_DB_DATA Certs2[];
  // /// ...
  // /// AUTH_CERT_DB_DATA Certsn[];
  //

  @param[in]  VariableName   Name of authenticated Variable.
  @param[in]  VendorGuid     Vendor GUID of authenticated Variable.
  @param[in]  Data           Pointer to variable "certdb" or "certdbv".
  @param[in]  DataSize       Size of variable "certdb" or "certdbv".
  @param[out] CertOffset     Offset of matching CertData, from starting of Data.
  @param[out] CertDataSize   Length of CertData in bytes.
  @param[out] CertNodeOffset Offset of matching AUTH_CERT_DB_DATA , from
                             starting of Data.
  @param[out] CertNodeSize   Length of AUTH_CERT_DB_DATA in bytes.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_NOT_FOUND         Fail to find matching certs.
  @retval  EFI_SUCCESS           Find matching certs and output parameters.

**/
EFI_STATUS
FindCertsFromDb(UTF16 *VariableName, EFI_GUID *VendorGuid,
                uint8_t *Data, uint64_t DataSize,
                uint32_t *CertOffset, uint32_t *CertDataSize,
                uint32_t *CertNodeOffset, uint32_t *CertNodeSize)
{
	uint32_t Offset;
	AUTH_CERT_DB_DATA *Ptr;
	uint32_t CertSize;
	uint32_t NameSize;
	uint32_t NodeSize;
	uint32_t CertDbListSize;

	if ((VariableName == NULL) || (VendorGuid == NULL) || (Data == NULL)) {
		return EFI_INVALID_PARAMETER;
	}

	//
	// Check whether DataSize matches recorded CertDbListSize.
	//
	if (DataSize < sizeof(uint32_t)) {
		return EFI_INVALID_PARAMETER;
	}

	CertDbListSize = *((uint32_t *)Data);

	if (CertDbListSize != (uint32_t)DataSize) {
		return EFI_INVALID_PARAMETER;
	}

	Offset = sizeof(uint32_t);

	//
	// Get corresponding certificates by VendorGuid and VariableName.
	//
	while (Offset < (uint32_t)DataSize) {
		Ptr = (AUTH_CERT_DB_DATA *)(Data + Offset);
		//
		// Check whether VendorGuid matches.
		//
		if (CompareGuid(&Ptr->VendorGuid, VendorGuid)) {
			NodeSize = *((uint32_t*)&Ptr->CertNodeSize);
			NameSize = *((uint32_t*)&Ptr->NameSize);
			CertSize = *((uint32_t*)&Ptr->CertDataSize);

			if (NodeSize != sizeof(EFI_GUID) + sizeof(uint32_t) * 3 +
						CertSize +
						sizeof(UTF16) * NameSize) {
				return EFI_INVALID_PARAMETER;
			}

			Offset = Offset + sizeof(EFI_GUID) + sizeof(uint32_t) * 3;
			//
			// Check whether VariableName matches.
			//
			if ((NameSize == strlen16(VariableName)) &&
			    (memcmp(Data + Offset, VariableName,
					NameSize * sizeof(UTF16)) == 0)) {
				Offset = Offset + NameSize * sizeof(UTF16);

				if (CertOffset != NULL) {
					*CertOffset = Offset;
				}

				if (CertDataSize != NULL) {
					*CertDataSize = CertSize;
				}

				if (CertNodeOffset != NULL) {
					*CertNodeOffset =
						(uint32_t)((uint8_t *)Ptr - Data);
				}

				if (CertNodeSize != NULL) {
					*CertNodeSize = NodeSize;
				}

				return EFI_SUCCESS;
			} else {
				Offset = Offset + NameSize * sizeof(UTF16) +
					 CertSize;
			}
		} else {
			NodeSize = *((uint32_t*)&Ptr->CertNodeSize);
			Offset = Offset + NodeSize;
		}
	}

	return EFI_NOT_FOUND;
}

/**
  Update the variable region with Variable information.

  @param[in] VariableName           Name of variable.
  @param[in] VendorGuid             Guid of variable.
  @param[in] Data                   Data pointer.
  @param[in] DataSize               Size of Data.
  @param[in] Attributes             Attribute value of the variable.

  @retval EFI_SUCCESS               The update operation is success.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.

**/
EFI_STATUS
AuthServiceInternalUpdateVariable(UTF16 *VariableName,
				  EFI_GUID *VendorGuid, void *Data,
				  uint64_t DataSize, uint32_t Attributes)
{
	AUTH_VARIABLE_INFO AuthVariableInfo;

	memset(&AuthVariableInfo, 0, sizeof(AuthVariableInfo));
	AuthVariableInfo.VariableName = VariableName;
	AuthVariableInfo.VendorGuid = VendorGuid;
	AuthVariableInfo.Data = Data;
	AuthVariableInfo.DataSize = DataSize;
	AuthVariableInfo.Attributes = Attributes;

    return ramdb_set(VariableName, Data, DataSize, Attributes) < 0 ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

/**
  Delete matching signer's certificates when deleting common authenticated
  variable by corresponding VariableName and VendorGuid from "certdb" or 
  "certdbv" according to authenticated variable attributes.

  @param[in]  VariableName   Name of authenticated Variable.
  @param[in]  VendorGuid     Vendor GUID of authenticated Variable.
  @param[in]  Attributes        Attributes of authenticated variable.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_NOT_FOUND         Fail to find "certdb"/"certdbv" or matching certs.
  @retval  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @retval  EFI_SUCCESS           The operation is completed successfully.

**/
EFI_STATUS
DeleteCertsFromDb(UTF16 *VariableName, EFI_GUID *VendorGuid,
		  uint32_t Attributes)
{
	EFI_STATUS Status;
	uint8_t *Data;
	uint64_t DataSize;
	uint32_t VarAttr;
	uint32_t CertNodeOffset;
	uint32_t CertNodeSize;
	uint8_t *NewCertDb;
	uint32_t NewCertDbSize;
	UTF16 *DbName;

	if ((VariableName == NULL) || (VendorGuid == NULL)) {
		return EFI_INVALID_PARAMETER;
	}

	if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
		//
		// Get variable "certdb".
		//
		DbName = CERT_DB_NAME;
		VarAttr = EFI_VARIABLE_NON_VOLATILE |
			  EFI_VARIABLE_RUNTIME_ACCESS |
			  EFI_VARIABLE_BOOTSERVICE_ACCESS |
			  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	} else {
		//
		// Get variable "certdbv".
		//
		DbName = CERT_DBV_NAME;
		VarAttr = EFI_VARIABLE_RUNTIME_ACCESS |
			  EFI_VARIABLE_BOOTSERVICE_ACCESS |
			  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	}

	Status = AuthServiceInternalFindVariable(DbName, &gEfiCertDbGuid,
						 (void **)&Data, &DataSize, NULL);

	if (EFI_ERROR(Status)) {
		return Status;
	}

	if ((DataSize == 0) || (Data == NULL)) {
		assert(false);
		return EFI_NOT_FOUND;
	}

	if (DataSize == sizeof(uint32_t)) {
		//
		// There is no certs in "certdb" or "certdbv".
		//
		return EFI_SUCCESS;
	}

	//
	// Get corresponding cert node from "certdb" or "certdbv".
	//
	Status = FindCertsFromDb(VariableName, VendorGuid, Data, DataSize, NULL,
				 NULL, &CertNodeOffset, &CertNodeSize);

	if (EFI_ERROR(Status)) {
		return Status;
	}

	if (DataSize < (CertNodeOffset + CertNodeSize)) {
		return EFI_NOT_FOUND;
	}

	//
	// Construct new data content of variable "certdb" or "certdbv".
	//
	NewCertDbSize = (uint32_t)DataSize - CertNodeSize;
	NewCertDb = (uint8_t *)mCertDbStore;

	//
	// Copy the DB entries before deleting node.
	//
	memcpy(NewCertDb, Data, CertNodeOffset);
	//
	// Update CertDbListSize.
	//
	memcpy(NewCertDb, &NewCertDbSize, sizeof(uint32_t));
	//
	// Copy the DB entries after deleting node.
	//
	if (DataSize > (CertNodeOffset + CertNodeSize)) {
		memcpy(NewCertDb + CertNodeOffset,
			Data + CertNodeOffset + CertNodeSize,
			DataSize - CertNodeOffset - CertNodeSize);
	}

	//
	// Set "certdb" or "certdbv".
	//
	Status = AuthServiceInternalUpdateVariable(
		DbName, &gEfiCertDbGuid, NewCertDb, NewCertDbSize, VarAttr);

	return Status;
}

/**
  Filter out the duplicated EFI_SIGNATURE_DATA from the new data by comparing to the original data.

  @param[in]        Data          Pointer to original EFI_SIGNATURE_LIST.
  @param[in]        DataSize      Size of Data buffer.
  @param[in, out]   NewData       Pointer to new EFI_SIGNATURE_LIST.
  @param[in, out]   NewDataSize   Size of NewData buffer.

**/
EFI_STATUS
FilterSignatureList(void *Data, uint64_t DataSize, void *NewData,
		    uint64_t *NewDataSize)
{
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert;
	uint64_t CertCount;
	EFI_SIGNATURE_LIST *NewCertList;
	EFI_SIGNATURE_DATA *NewCert;
	uint64_t NewCertCount;
	uint64_t Index;
	uint64_t Index2;
	uint64_t Size;
	uint8_t *Tail;
	uint64_t CopiedCount;
	uint64_t SignatureListSize;
	bool IsNewCert;
	uint8_t *TempData;
	uint64_t TempDataSize;

	if (*NewDataSize == 0) {
		return EFI_SUCCESS;
	}

	TempDataSize = *NewDataSize;
    TempData = malloc(TempDataSize);
	if ( !TempData )
		return EFI_OUT_OF_RESOURCES;

	Tail = TempData;

	NewCertList = (EFI_SIGNATURE_LIST *)NewData;
	while ((*NewDataSize > 0) &&
	       (*NewDataSize >= NewCertList->SignatureListSize)) {
		NewCert =
			(EFI_SIGNATURE_DATA *)((uint8_t *)NewCertList +
					       sizeof(EFI_SIGNATURE_LIST) +
					       NewCertList->SignatureHeaderSize);
		NewCertCount = (NewCertList->SignatureListSize -
				sizeof(EFI_SIGNATURE_LIST) -
				NewCertList->SignatureHeaderSize) /
			       NewCertList->SignatureSize;

		CopiedCount = 0;
		for (Index = 0; Index < NewCertCount; Index++) {
			IsNewCert = true;

			Size = DataSize;
			CertList = (EFI_SIGNATURE_LIST *)Data;
			while ((Size > 0) &&
			       (Size >= CertList->SignatureListSize)) {
				if (CompareGuid(&CertList->SignatureType,
						&NewCertList->SignatureType) &&
				    (CertList->SignatureSize ==
				     NewCertList->SignatureSize)) {
					Cert = (EFI_SIGNATURE_DATA
							*)((uint8_t *)CertList +
							   sizeof(EFI_SIGNATURE_LIST) +
							   CertList->SignatureHeaderSize);
					CertCount =
						(CertList->SignatureListSize -
						 sizeof(EFI_SIGNATURE_LIST) -
						 CertList->SignatureHeaderSize) /
						CertList->SignatureSize;
					for (Index2 = 0; Index2 < CertCount;
					     Index2++) {
						//
						// Iterate each Signature Data in this Signature List.
						//
						if (memcmp(
							    NewCert, Cert,
							    CertList->SignatureSize) ==
						    0) {
							IsNewCert = false;
							break;
						}
						Cert = (EFI_SIGNATURE_DATA
								*)((uint8_t *)Cert +
								   CertList->SignatureSize);
					}
				}

				if (!IsNewCert) {
					break;
				}
				Size -= CertList->SignatureListSize;
				CertList =
					(EFI_SIGNATURE_LIST
						 *)((uint8_t *)CertList +
						    CertList->SignatureListSize);
			}

			if (IsNewCert) {
				//
				// New EFI_SIGNATURE_DATA, keep it.
				//
				if (CopiedCount == 0) {
					//
					// Copy EFI_SIGNATURE_LIST header for only once.
					//
					memcpy(Tail, NewCertList,
						sizeof(EFI_SIGNATURE_LIST) +
							NewCertList
								->SignatureHeaderSize);
					Tail = Tail +
					       sizeof(EFI_SIGNATURE_LIST) +
					       NewCertList->SignatureHeaderSize;
				}

				memcpy(Tail, NewCert,
					NewCertList->SignatureSize);
				Tail += NewCertList->SignatureSize;
				CopiedCount++;
			}

			NewCert =
				(EFI_SIGNATURE_DATA *)((uint8_t *)NewCert +
						       NewCertList
							       ->SignatureSize);
		}

		//
		// Update SignatureListSize in the kept EFI_SIGNATURE_LIST.
		//
		if (CopiedCount != 0) {
			SignatureListSize =
				sizeof(EFI_SIGNATURE_LIST) +
				NewCertList->SignatureHeaderSize +
				(CopiedCount * NewCertList->SignatureSize);
			CertList = (EFI_SIGNATURE_LIST *)(Tail -
							  SignatureListSize);
			CertList->SignatureListSize = (uint32_t)SignatureListSize;
		}

		*NewDataSize -= NewCertList->SignatureListSize;
		NewCertList =
			(EFI_SIGNATURE_LIST *)((uint8_t *)NewCertList +
					       NewCertList->SignatureListSize);
	}

	TempDataSize = (Tail - (uint8_t *)TempData);

	memcpy(NewData, TempData, TempDataSize);
	*NewDataSize = TempDataSize;

	return EFI_SUCCESS;
}


/**
  Update the variable region with Variable information.

  @param[in] VariableName           Name of variable.
  @param[in] VendorGuid             Guid of variable.
  @param[in] Data                   Data pointer.
  @param[in] DataSize               Size of Data.
  @param[in] Attributes             Attribute value of the variable.
  @param[in] TimeStamp              Value of associated TimeStamp.

  @retval EFI_SUCCESS               The update operation is success.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.

**/
EFI_STATUS
AuthServiceInternalUpdateVariableWithTimeStamp(UTF16 *VariableName,
					       EFI_GUID *VendorGuid,
					       void *Data, uint64_t DataSize,
					       uint32_t Attributes,
					       EFI_TIME *TimeStamp)
{
	EFI_STATUS FindStatus;
	void *OrgData;
	uint64_t OrgDataSize;
	AUTH_VARIABLE_INFO AuthVariableInfo;

	FindStatus = AuthServiceInternalFindVariable(VariableName, VendorGuid,
						     &OrgData, &OrgDataSize, NULL);

	//
	// EFI_VARIABLE_APPEND_WRITE attribute only effects for existing variable
	//
	if (!EFI_ERROR(FindStatus) &&
	    ((Attributes & EFI_VARIABLE_APPEND_WRITE) != 0)) {
		if ((CompareGuid(VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
		     ((strcmp16(VariableName, DB_NAME) == 0) ||
		      (strcmp16(VariableName, DBX_NAME) ==
		       0) ||
		      (strcmp16(VariableName, DBT_NAME) ==
		       0))) ||
		    (CompareGuid(VendorGuid, &gEfiGlobalVariableGuid) &&
		     (strcmp16(VariableName, KEK_NAME) == 0))) {
			//
			// For variables with formatted as EFI_SIGNATURE_LIST, the driver shall not perform an append of
			// EFI_SIGNATURE_DATA values that are already part of the existing variable value.
			//
			FilterSignatureList(OrgData, OrgDataSize, Data,
					    &DataSize);
		}
	}

	memset(&AuthVariableInfo, 0, sizeof(AuthVariableInfo));
	AuthVariableInfo.VariableName = VariableName;
	AuthVariableInfo.VendorGuid = VendorGuid;
	AuthVariableInfo.Data = Data;
	AuthVariableInfo.DataSize = DataSize;
	AuthVariableInfo.Attributes = Attributes;
	AuthVariableInfo.TimeStamp = TimeStamp;

    return ramdb_set(VariableName, Data, DataSize, Attributes) < 0 ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

/**
  Determine whether this operation needs a physical present user.

  @param[in]      VariableName            Name of the Variable.
  @param[in]      VendorGuid              GUID of the Variable.

  @retval true      This variable is protected, only a physical present user could set this variable.
  @retval false     This variable is not protected.

**/
bool
NeedPhysicallyPresent(UTF16 *VariableName, EFI_GUID *VendorGuid)
{
	if ((CompareGuid(VendorGuid, &gEfiSecureBootEnableDisableGuid) &&
	     (strcmp16(VariableName, SECURE_BOOT_NAME) == 0)) ||
	    (CompareGuid(VendorGuid, &gEfiCustomModeEnableGuid) &&
	     (strcmp16(VariableName, CUSTOM_MODE_NAME) == 0))) {
		return true;
	}

	return false;
}

/**
  Determine whether the platform is operating in Custom Secure Boot mode.

  @retval true           The platform is operating in Custom mode.
  @retval false          The platform is operating in Standard mode.

**/
bool
InCustomMode(void)
{
	EFI_STATUS Status;
	void *Data;
	uint64_t DataSize;

	Status = AuthServiceInternalFindVariable(CUSTOM_MODE_NAME,
						 &gEfiCustomModeEnableGuid,
						 &Data, &DataSize, NULL);
	if (!EFI_ERROR(Status) && (*(uint8_t *)Data == CUSTOM_SECURE_BOOT_MODE)) {
		return true;
	}

	return false;
}

/**
  Update platform mode.

  @param[in]      Mode                    SETUP_MODE or USER_MODE.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SUCCESS                     Update platform mode successfully.

**/
EFI_STATUS
UpdatePlatformMode(uint32_t Mode)
{
	EFI_STATUS Status;
	void *Data;
	uint64_t DataSize;
	uint8_t SecureBootMode;
	uint8_t SecureBootEnable;
	uint64_t VariableDataSize;

	Status = AuthServiceInternalFindVariable(
		SETUP_MODE_NAME, &gEfiGlobalVariableGuid, &Data, &DataSize, NULL);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	//
	// Update the value of SetupMode variable by a simple mem copy, this could avoid possible
	// variable storage reclaim at runtime.
	//
	mPlatformMode = (uint8_t)Mode;
	memcpy(Data, &mPlatformMode, sizeof(uint8_t));

    /*
     * TODO: is it possible to determine that we are at Runtime from
     * inside the vars service? I do not think so.
     */
#if 0
	if (mAuthVarLibContextIn->AtRuntime()) {
		//
		// SecureBoot Variable indicates whether the platform firmware is operating
		// in Secure boot mode (1) or not (0), so we should not change SecureBoot
		// Variable in runtime.
		//
		return Status;
	}
#endif

	//
	// Check "SecureBoot" variable's existence.
	// If it doesn't exist, firmware has no capability to perform driver signing verification,
	// then set "SecureBoot" to 0.
	//
	Status = AuthServiceInternalFindVariable(SECURE_BOOT_MODE_NAME,
						 &gEfiGlobalVariableGuid, &Data,
						 &DataSize, NULL);
	//
	// If "SecureBoot" variable exists, then check "SetupMode" variable update.
	// If "SetupMode" variable is USER_MODE, "SecureBoot" variable is set to 1.
	// If "SetupMode" variable is SETUP_MODE, "SecureBoot" variable is set to 0.
	//
	if (EFI_ERROR(Status)) {
		SecureBootMode = SECURE_BOOT_MODE_DISABLE;
	} else {
		if (mPlatformMode == USER_MODE) {
			SecureBootMode = SECURE_BOOT_MODE_ENABLE;
		} else if (mPlatformMode == SETUP_MODE) {
			SecureBootMode = SECURE_BOOT_MODE_DISABLE;
		} else {
			return EFI_NOT_FOUND;
		}
	}

	Status = AuthServiceInternalUpdateVariable(
		SECURE_BOOT_MODE_NAME, &gEfiGlobalVariableGuid,
		&SecureBootMode, sizeof(uint8_t),
		EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	//
	// Check "SecureBootEnable" variable's existence. It can enable/disable secure boot feature.
	//
	Status = AuthServiceInternalFindVariable(
		SECURE_BOOT_NAME, &gEfiSecureBootEnableDisableGuid,
		&Data, &DataSize, NULL);

	if (SecureBootMode == SECURE_BOOT_MODE_ENABLE) {
		//
		// Create the "SecureBootEnable" variable as secure boot is enabled.
		//
		SecureBootEnable = SECURE_BOOT_ENABLE;
		VariableDataSize = sizeof(SecureBootEnable);
	} else {
		//
		// Delete the "SecureBootEnable" variable if this variable exist as "SecureBoot"
		// variable is not in secure boot state.
		//
		if (EFI_ERROR(Status)) {
			return EFI_SUCCESS;
		}
		SecureBootEnable = SECURE_BOOT_DISABLE;
		VariableDataSize = 0;
	}

	Status = AuthServiceInternalUpdateVariable(
		SECURE_BOOT_NAME, &gEfiSecureBootEnableDisableGuid,
		&SecureBootEnable, VariableDataSize,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS);
	return Status;
}

/**
  Check input data form to make sure it is a valid EFI_SIGNATURE_LIST for PK/KEK/db/dbx/dbt variable.

  @param[in]  VariableName                Name of Variable to be check.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Point to the variable data to be checked.
  @param[in]  DataSize                    Size of Data.

  @return EFI_INVALID_PARAMETER           Invalid signature list format.
  @return EFI_SUCCESS                     Passed signature list format check successfully.

**/
EFI_STATUS
CheckSignatureListFormat(UTF16 *VariableName, EFI_GUID *VendorGuid,
			 void *Data, uint64_t DataSize)
{
	EFI_SIGNATURE_LIST *SigList;
	uint64_t SigDataSize;
	uint32_t Index;
	uint32_t SigCount;
	bool IsPk;
	void *RsaContext;
	EFI_SIGNATURE_DATA *CertData;
	uint64_t CertLen;

	if (DataSize == 0) {
		return EFI_SUCCESS;
	}

	assert(VariableName != NULL && VendorGuid != NULL && Data != NULL);

	if (CompareGuid(VendorGuid, &gEfiGlobalVariableGuid) &&
	    (strcmp16(VariableName, PK_NAME) == 0)) {
		IsPk = true;
	} else if ((CompareGuid(VendorGuid, &gEfiGlobalVariableGuid) &&
		    (strcmp16(VariableName, KEK_NAME) == 0)) ||
		   (CompareGuid(VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
		    ((strcmp16(VariableName, DB_NAME) == 0) ||
		     (strcmp16(VariableName, DBX_NAME) == 0) ||
		     (strcmp16(VariableName, DBT_NAME) ==
		      0)))) {
		IsPk = false;
	} else {
		return EFI_SUCCESS;
	}

	SigCount = 0;
	SigList = (EFI_SIGNATURE_LIST *)Data;
	SigDataSize = DataSize;
	RsaContext = NULL;

	//
	// Walk throuth the input signature list and check the data format.
	// If any signature is incorrectly formed, the whole check will fail.
	//
	while ((SigDataSize > 0) &&
	       (SigDataSize >= SigList->SignatureListSize)) {
		for (Index = 0; Index < (sizeof(mSupportSigItem) /
					 sizeof(EFI_SIGNATURE_ITEM));
		     Index++) {
			if (CompareGuid(&SigList->SignatureType,
					&mSupportSigItem[Index].SigType)) {
				//
				// The value of SignatureSize should always be 16 (size of SignatureOwner
				// component) add the data length according to signature type.
				//
				if (mSupportSigItem[Index].SigDataSize !=
					    ((uint32_t)~0) &&
				    (SigList->SignatureSize -
				     sizeof(EFI_GUID)) !=
					    mSupportSigItem[Index].SigDataSize) {
					return EFI_INVALID_PARAMETER;
				}
				if (mSupportSigItem[Index].SigHeaderSize !=
					    ((uint32_t)~0) &&
				    SigList->SignatureHeaderSize !=
					    mSupportSigItem[Index]
						    .SigHeaderSize) {
					return EFI_INVALID_PARAMETER;
				}
				break;
			}
		}

		if (Index ==
		    (sizeof(mSupportSigItem) / sizeof(EFI_SIGNATURE_ITEM))) {
			//
			// Undefined signature type.
			//
			return EFI_INVALID_PARAMETER;
		}

		if (CompareGuid(&SigList->SignatureType, &gEfiCertX509Guid)) {
			//
			// Try to retrieve the RSA public key from the X.509 certificate.
			// If this operation fails, it's not a valid certificate.
			//
			RsaContext = RsaNew();
			if (RsaContext == NULL) {
				return EFI_INVALID_PARAMETER;
			}
			CertData = (EFI_SIGNATURE_DATA
					    *)((uint8_t *)SigList +
					       sizeof(EFI_SIGNATURE_LIST) +
					       SigList->SignatureHeaderSize);
			CertLen = SigList->SignatureSize - sizeof(EFI_GUID);
			if (!RsaGetPublicKeyFromX509(CertData->SignatureData,
						     CertLen, &RsaContext)) {
				RsaFree(RsaContext);
				return EFI_INVALID_PARAMETER;
			}
			RsaFree(RsaContext);
		}

		if ((SigList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
		     SigList->SignatureHeaderSize) %
			    SigList->SignatureSize !=
		    0) {
			return EFI_INVALID_PARAMETER;
		}
		SigCount += (SigList->SignatureListSize -
			     sizeof(EFI_SIGNATURE_LIST) -
			     SigList->SignatureHeaderSize) /
			    SigList->SignatureSize;

		SigDataSize -= SigList->SignatureListSize;
		SigList = (EFI_SIGNATURE_LIST *)((uint8_t *)SigList +
						 SigList->SignatureListSize);
	}

	if (((uint64_t)SigList - (uint64_t)Data) != DataSize) {
		return EFI_INVALID_PARAMETER;
	}

	if (IsPk && SigCount > 1) {
		return EFI_INVALID_PARAMETER;
	}

	return EFI_SUCCESS;
}

/**
  Update "VendorKeys" variable to record the out of band secure boot key modification.

  @return EFI_SUCCESS           Variable is updated successfully.
  @return Others                Failed to update variable.

**/
EFI_STATUS
VendorKeyIsModified(void)
{
	EFI_STATUS Status;

	if (mVendorKeyState == VENDOR_KEYS_MODIFIED) {
		return EFI_SUCCESS;
	}
	mVendorKeyState = VENDOR_KEYS_MODIFIED;

	Status = AuthServiceInternalUpdateVariable(
		VENDOR_KEYS_NV_NAME, &gEfiVendorKeysNvGuid,
		&mVendorKeyState, sizeof(uint8_t),
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
			EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	return AuthServiceInternalUpdateVariable(
		VENDOR_KEYS_NAME, &gEfiGlobalVariableGuid,
		&mVendorKeyState, sizeof(uint8_t),
		EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);
}

/**
  Process variable with platform key for verification.

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable
  @param[in]  IsPk                        Indicate whether it is to process pk.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation.
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable passed validation successfully.

**/
EFI_STATUS
ProcessVarWithPk(UTF16 *VariableName, EFI_GUID *VendorGuid,
		 void *Data, uint64_t DataSize,
		 uint32_t Attributes, bool IsPk)
{
	EFI_STATUS Status;
	bool Del;
	uint8_t *Payload;
	uint64_t PayloadSize;

	if ((Attributes & EFI_VARIABLE_NON_VOLATILE) == 0 ||
	    (Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) ==
		    0) {
		//
		// PK, KEK and db/dbx/dbt should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
		// authenticated variable.
		//
		return EFI_INVALID_PARAMETER;
	}

	//
	// Init state of Del. State may change due to secure check
	//
	Del = false;
	if ((InCustomMode() && UserPhysicalPresent()) ||
	    (mPlatformMode == SETUP_MODE && !IsPk)) {
		Payload = (uint8_t *)Data + AUTHINFO2_SIZE(Data);
		PayloadSize = DataSize - AUTHINFO2_SIZE(Data);
		if (PayloadSize == 0) {
			Del = true;
		}

		Status = CheckSignatureListFormat(VariableName, VendorGuid,
						  Payload, PayloadSize);
		if (EFI_ERROR(Status)) {
			return Status;
		}

		Status = AuthServiceInternalUpdateVariableWithTimeStamp(
			VariableName, VendorGuid, Payload, PayloadSize,
			Attributes,
			&((EFI_VARIABLE_AUTHENTICATION_2 *)Data)->TimeStamp);

        if (EFI_ERROR(Status)) {
			return Status;
		}

		if ((mPlatformMode != SETUP_MODE) || IsPk) {
			Status = VendorKeyIsModified();
		}
	} else if (mPlatformMode == USER_MODE) {
		//
		// Verify against X509 Cert in PK database.
		//
		Status = VerifyTimeBasedPayloadAndUpdate(VariableName,
							 VendorGuid, Data,
							 DataSize, Attributes,
							 AuthVarTypePk, &Del);
	} else {
		//
		// Verify against the certificate in data payload.
		//
		Status = VerifyTimeBasedPayloadAndUpdate(
			VariableName, VendorGuid, Data, DataSize, Attributes,
			AuthVarTypePayload, &Del);
	}

	if (!EFI_ERROR(Status) && IsPk) {
		if (mPlatformMode == SETUP_MODE && !Del) {
			//
			// If enroll PK in setup mode, need change to user mode.
			//
			Status = UpdatePlatformMode(USER_MODE);
		} else if (mPlatformMode == USER_MODE && Del) {
			//
			// If delete PK in user mode, need change to setup mode.
			//
			Status = UpdatePlatformMode(SETUP_MODE);
		}
	}

	return Status;
}

/**
  Process variable with key exchange key for verification.

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
ProcessVarWithKek(UTF16 *VariableName, EFI_GUID *VendorGuid,
		  void *Data, uint64_t DataSize,
		  uint32_t Attributes)
{
	EFI_STATUS Status;
	uint8_t *Payload;
	uint64_t PayloadSize;

	if ((Attributes & EFI_VARIABLE_NON_VOLATILE) == 0 ||
	    (Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) ==
		    0) {
		//
		// DB, DBX and DBT should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
		// authenticated variable.
		//
		return EFI_INVALID_PARAMETER;
	}

	Status = EFI_SUCCESS;
	if (mPlatformMode == USER_MODE &&
	    !(InCustomMode() && UserPhysicalPresent())) {
		//
		// Time-based, verify against X509 Cert KEK.
		//
		return VerifyTimeBasedPayloadAndUpdate(VariableName, VendorGuid,
						       Data, DataSize,
						       Attributes,
						       AuthVarTypeKek, NULL);
	} else {
		//
		// If in setup mode or custom secure boot mode, no authentication needed.
		//
		Payload = (uint8_t *)Data + AUTHINFO2_SIZE(Data);
		PayloadSize = DataSize - AUTHINFO2_SIZE(Data);

		Status = CheckSignatureListFormat(VariableName, VendorGuid,
						  Payload, PayloadSize);
		if (EFI_ERROR(Status)) {
			return Status;
		}

		Status = AuthServiceInternalUpdateVariableWithTimeStamp(
			VariableName, VendorGuid, Payload, PayloadSize,
			Attributes,
			&((EFI_VARIABLE_AUTHENTICATION_2 *)Data)->TimeStamp);
		if (EFI_ERROR(Status)) {
			return Status;
		}

		if (mPlatformMode != SETUP_MODE) {
			Status = VendorKeyIsModified();
		}
	}

	return Status;
}

/**
  Check if it is to delete auth variable.

  @param[in] OrgAttributes      Original attribute value of the variable.
  @param[in] Data               Data pointer.
  @param[in] DataSize           Size of Data.
  @param[in] Attributes         Attribute value of the variable.

  @retval true                  It is to delete auth variable.
  @retval false                 It is not to delete auth variable.

**/
bool
IsDeleteAuthVariable(uint32_t OrgAttributes, void *Data, uint64_t DataSize,
		     uint32_t Attributes)
{
	bool Del;
	uint64_t PayloadSize;

	Del = false;

	//
	// To delete a variable created with the EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
	// or the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute,
	// SetVariable must be used with attributes matching the existing variable
	// and the DataSize set to the size of the AuthInfo descriptor.
	//
	if ((Attributes == OrgAttributes) &&
	    ((Attributes &
	      (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
	       EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) != 0)) {
		if ((Attributes &
		     EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
			PayloadSize = DataSize - AUTHINFO2_SIZE(Data);
			if (PayloadSize == 0) {
				Del = true;
			}
		} else {
			PayloadSize = DataSize - AUTHINFO_SIZE;
			if (PayloadSize == 0) {
				Del = true;
			}
		}
	}

	return Del;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @param[in]  VariableName                Name of the variable.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data.
  @param[in]  Attributes                  Attribute value of the variable.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_WRITE_PROTECTED             Variable is write-protected and needs authentication with
                                          EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS or EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set.
  @return EFI_OUT_OF_RESOURCES            The Database to save the public key is full.
  @return EFI_SECURITY_VIOLATION          The variable is with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                                          set, but the AuthInfo does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable is not write-protected or pass validation successfully.

**/
EFI_STATUS
ProcessVariable(UTF16 *VariableName, EFI_GUID *VendorGuid, void *Data,
		uint64_t DataSize, uint32_t Attributes)
{
	EFI_STATUS Status;
    void *Buffer;
    size_t BufferSize;
    uint32_t TempAttributes;
    EFI_TIME *TimeStamp;
	AUTH_VARIABLE_INFO OrgVariableInfo;

	Status = EFI_SUCCESS;

	Status = AuthServiceInternalFindVariable(VariableName, VendorGuid,
                                             &Buffer, &BufferSize, &TempAttributes);

	if (EFI_ERROR(Status)) {
        return Status;
    }

    OrgVariableInfo.VariableName = VariableName;
    OrgVariableInfo.VendorGuid = VendorGuid;
    OrgVariableInfo.Attributes = Attributes;
    OrgVariableInfo.DataSize = DataSize;
    OrgVariableInfo.Data = Buffer;

//    OrgVariableInfo.TimeStamp = get_time_stamp(VariableName, VendorGuid);

	if ((!EFI_ERROR(Status)) &&
	    IsDeleteAuthVariable(OrgVariableInfo.Attributes, Data, DataSize,
				 Attributes) &&
	    UserPhysicalPresent()) {
		//
		// Allow the delete operation of common authenticated variable(AT or AW) at user physical presence.
		//
		Status = AuthServiceInternalUpdateVariable(
			VariableName, VendorGuid, NULL, 0, 0);
		if (!EFI_ERROR(Status) &&
		    ((Attributes &
		      EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) !=
		     0)) {
			Status = DeleteCertsFromDb(VariableName, VendorGuid,
						   Attributes);
		}

        free(Data);
		return Status;
	}

	if (NeedPhysicallyPresent(VariableName, VendorGuid) &&
	    !UserPhysicalPresent()) {
		//
		// This variable is protected, only physical present user could modify its value.
		//
        free(Data);
		return EFI_SECURITY_VIOLATION;
	}

	//
	if ((Attributes & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != 0) {
		//
		// Reject Counter Based Auth Variable processing request.
		//
        free(Data);
		return EFI_UNSUPPORTED;
	} else if ((Attributes &
		    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
		//
		// Process Time-based Authenticated variable.
		//
        free(Data);
		return VerifyTimeBasedPayloadAndUpdate(VariableName, VendorGuid,
						       Data, DataSize,
						       Attributes,
						       AuthVarTypePriv, NULL);
	}

	if ((OrgVariableInfo.Data != NULL) &&
	    ((OrgVariableInfo.Attributes &
	      (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
	       EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) != 0)) {
		//
		// If the variable is already write-protected, it always needs authentication before update.
		//
        free(Data);
		return EFI_WRITE_PROTECTED;
	}

	//
	// Not authenticated variable, just update variable as usual.
	//
	Status = AuthServiceInternalUpdateVariable(VariableName, VendorGuid,
						   Data, DataSize, Attributes);
    free(Data);
	return Status;
}

/**
  Compare two EFI_TIME data.


  @param FirstTime           A pointer to the first EFI_TIME data.
  @param SecondTime          A pointer to the second EFI_TIME data.

  @retval  true              The FirstTime is not later than the SecondTime.
  @retval  false             The FirstTime is later than the SecondTime.

**/
bool
AuthServiceInternalCompareTimeStamp(EFI_TIME *FirstTime,
				    EFI_TIME *SecondTime)
{
	if (FirstTime->Year != SecondTime->Year) {
		return (bool)(FirstTime->Year < SecondTime->Year);
	} else if (FirstTime->Month != SecondTime->Month) {
		return (bool)(FirstTime->Month < SecondTime->Month);
	} else if (FirstTime->Day != SecondTime->Day) {
		return (bool)(FirstTime->Day < SecondTime->Day);
	} else if (FirstTime->Hour != SecondTime->Hour) {
		return (bool)(FirstTime->Hour < SecondTime->Hour);
	} else if (FirstTime->Minute != SecondTime->Minute) {
		return (bool)(FirstTime->Minute < SecondTime->Minute);
	}

	return (bool)(FirstTime->Second <= SecondTime->Second);
}

/**
  Calculate SHA256 digest of SignerCert CommonName + ToplevelCert tbsCertificate
  SignerCert and ToplevelCert are inside the signer certificate chain.

  @param[in]  SignerCert          A pointer to SignerCert data.
  @param[in]  SignerCertSize      Length of SignerCert data.
  @param[in]  TopLevelCert        A pointer to TopLevelCert data.
  @param[in]  TopLevelCertSize    Length of TopLevelCert data.
  @param[out] Sha256Digest       Sha256 digest calculated.

  @return EFI_ABORTED          Digest process failed.
  @return EFI_SUCCESS          SHA256 Digest is succesfully calculated.

**/
EFI_STATUS
CalculatePrivAuthVarSignChainSHA256Digest(uint8_t *SignerCert,
					  uint64_t SignerCertSize,
					  uint8_t *TopLevelCert,
					  uint64_t TopLevelCertSize,
					  uint8_t *Sha256Digest)
{
	uint8_t *TbsCert;
	uint64_t TbsCertSize;
	CHAR8 CertCommonName[128];
	uint64_t CertCommonNameSize;
	bool CryptoStatus;
	EFI_STATUS Status;

	CertCommonNameSize = sizeof(CertCommonName);

	//
	// Get SignerCert CommonName
	//
	Status = X509GetCommonName(SignerCert, SignerCertSize, CertCommonName,
				   &CertCommonNameSize);
	if (EFI_ERROR(Status)) {
		DEBUG("%s Get SignerCert CommonName failed with status %lx\n",
		       __func__, Status);
		return EFI_ABORTED;
	}

	//
	// Get TopLevelCert tbsCertificate
	//
	if (!X509GetTBSCert(TopLevelCert, TopLevelCertSize, &TbsCert,
			    &TbsCertSize)) {
		
		DEBUG("%s Get Top-level Cert tbsCertificate failed!\n",
		       __func__);
		return EFI_ABORTED;
	}

	//
	// Digest SignerCert CN + TopLevelCert tbsCertificate
	//
	memset(Sha256Digest, 0, SHA256_DIGEST_SIZE);
	CryptoStatus = Sha256Init(mHashCtx);
	if (!CryptoStatus) {
		return EFI_ABORTED;
	}

	//
	// '\0' is forced in CertCommonName. No overflow issue
	//
	CryptoStatus = Sha256Update(mHashCtx, CertCommonName,
				    strlen(CertCommonName));
	if (!CryptoStatus) {
		return EFI_ABORTED;
	}

	CryptoStatus = Sha256Update(mHashCtx, TbsCert, TbsCertSize);
	if (!CryptoStatus) {
		return EFI_ABORTED;
	}

	CryptoStatus = Sha256Final(mHashCtx, Sha256Digest);
	if (!CryptoStatus) {
		return EFI_ABORTED;
	}

	return EFI_SUCCESS;
}


/**
  Retrieve signer's certificates for common authenticated variable
  by corresponding VariableName and VendorGuid from "certdb"
  or "certdbv" according to authenticated variable attributes.

  @param[in]  VariableName   Name of authenticated Variable.
  @param[in]  VendorGuid     Vendor GUID of authenticated Variable.
  @param[in]  Attributes        Attributes of authenticated variable.
  @param[out] CertData       Pointer to signer's certificates.
  @param[out] CertDataSize   Length of CertData in bytes.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_NOT_FOUND         Fail to find "certdb"/"certdbv" or matching certs.
  @retval  EFI_SUCCESS           Get signer's certificates successfully.

**/
EFI_STATUS
GetCertsFromDb(UTF16 *VariableName, EFI_GUID *VendorGuid,
	       uint32_t Attributes, uint8_t **CertData,
	       uint32_t *CertDataSize)
{
	EFI_STATUS Status;
	uint8_t *Data;
	uint64_t DataSize;
	uint32_t CertOffset;
	UTF16 *DbName;

	if ((VariableName == NULL) || (VendorGuid == NULL) ||
	    (CertData == NULL) || (CertDataSize == NULL)) {
		return EFI_INVALID_PARAMETER;
	}

	if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
		//
		// Get variable "certdb".
		//
		DbName = CERT_DB_NAME;
	} else {
		//
		// Get variable "certdbv".
		//
		DbName = CERT_DBV_NAME;
	}

	//
	// Get variable "certdb" or "certdbv".
	//
	Status = AuthServiceInternalFindVariable(DbName, &gEfiCertDbGuid,
						 (void **)&Data, &DataSize, NULL);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	if ((DataSize == 0) || (Data == NULL)) {
		assert(false);
		return EFI_NOT_FOUND;
	}

	Status = FindCertsFromDb(VariableName, VendorGuid, Data, DataSize,
				 &CertOffset, CertDataSize, NULL, NULL);

	if (EFI_ERROR(Status)) {
		return Status;
	}

	*CertData = Data + CertOffset;
	return EFI_SUCCESS;
}

/**
  Insert signer's certificates for common authenticated variable with VariableName
  and VendorGuid in AUTH_CERT_DB_DATA to "certdb" or "certdbv" according to
  time based authenticated variable attributes. CertData is the SHA256 digest of
  SignerCert CommonName + TopLevelCert tbsCertificate.

  @param[in]  VariableName      Name of authenticated Variable.
  @param[in]  VendorGuid        Vendor GUID of authenticated Variable.
  @param[in]  Attributes        Attributes of authenticated variable.
  @param[in]  SignerCert        Signer certificate data.
  @param[in]  SignerCertSize    Length of signer certificate.
  @param[in]  TopLevelCert      Top-level certificate data.
  @param[in]  TopLevelCertSize  Length of top-level certificate.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_ACCESS_DENIED     An AUTH_CERT_DB_DATA entry with same VariableName
                                 and VendorGuid already exists.
  @retval  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @retval  EFI_SUCCESS           Insert an AUTH_CERT_DB_DATA entry to "certdb" or "certdbv"

**/
EFI_STATUS
InsertCertsToDb(UTF16 *VariableName, EFI_GUID *VendorGuid,
		uint32_t Attributes, uint8_t *SignerCert,
		uint64_t SignerCertSize, uint8_t *TopLevelCert,
		uint64_t TopLevelCertSize)
{
	EFI_STATUS Status;
	uint8_t *Data;
	uint64_t DataSize;
	uint32_t VarAttr;
	uint8_t *NewCertDb;
	uint32_t NewCertDbSize;
	uint32_t CertNodeSize;
	uint32_t NameSize;
	uint32_t CertDataSize;
	AUTH_CERT_DB_DATA *Ptr;
	UTF16 *DbName;
	uint8_t Sha256Digest[SHA256_DIGEST_SIZE];

	if ((VariableName == NULL) || (VendorGuid == NULL) ||
	    (SignerCert == NULL) || (TopLevelCert == NULL)) {
		return EFI_INVALID_PARAMETER;
	}

	if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
		//
		// Get variable "certdb".
		//
		DbName = CERT_DB_NAME;
		VarAttr = EFI_VARIABLE_NON_VOLATILE |
			  EFI_VARIABLE_RUNTIME_ACCESS |
			  EFI_VARIABLE_BOOTSERVICE_ACCESS |
			  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	} else {
		//
		// Get variable "certdbv".
		//
		DbName = CERT_DBV_NAME;
		VarAttr = EFI_VARIABLE_RUNTIME_ACCESS |
			  EFI_VARIABLE_BOOTSERVICE_ACCESS |
			  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	}

	//
	// Get variable "certdb" or "certdbv".
	//
	Status = AuthServiceInternalFindVariable(DbName, &gEfiCertDbGuid,
						 (void **)&Data, &DataSize, NULL);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	if ((DataSize == 0) || (Data == NULL)) {
		assert(false);
		return EFI_NOT_FOUND;
	}

	//
	// Find whether matching cert node already exists in "certdb" or "certdbv".
	// If yes return error.
	//
	Status = FindCertsFromDb(VariableName, VendorGuid, Data, DataSize, NULL,
				 NULL, NULL, NULL);

	if (!EFI_ERROR(Status))
    {
		assert(false);
		return EFI_ACCESS_DENIED;
	}

	//
	// Construct new data content of variable "certdb" or "certdbv".
	//
	NameSize = (uint32_t)strlen16(VariableName);
	CertDataSize = sizeof(Sha256Digest);
	CertNodeSize = sizeof(AUTH_CERT_DB_DATA) + (uint32_t)CertDataSize +
		       NameSize * sizeof(UTF16);
	NewCertDbSize = (uint32_t)DataSize + CertNodeSize;
	if (NewCertDbSize > mMaxCertDbSize)
    {
		return EFI_OUT_OF_RESOURCES;
	}

	Status = CalculatePrivAuthVarSignChainSHA256Digest(
		SignerCert, SignerCertSize, TopLevelCert, TopLevelCertSize,
		Sha256Digest);
	if (EFI_ERROR(Status))
    {
		return Status;
	}

	NewCertDb = (uint8_t *)mCertDbStore;

	//
	// Copy the DB entries before inserting node.
	//
	memcpy(NewCertDb, Data, DataSize);
	//
	// Update CertDbListSize.
	//
	memcpy(NewCertDb, &NewCertDbSize, sizeof(uint32_t));
	//
	// Construct new cert node.
	//
	Ptr = (AUTH_CERT_DB_DATA *)(NewCertDb + DataSize);
	memcpy(&Ptr->VendorGuid, VendorGuid, sizeof(EFI_GUID));
	memcpy(&Ptr->CertNodeSize, &CertNodeSize, sizeof(uint32_t));
	memcpy(&Ptr->NameSize, &NameSize, sizeof(uint32_t));
	memcpy(&Ptr->CertDataSize, &CertDataSize, sizeof(uint32_t));

	memcpy((uint8_t *)Ptr + sizeof(AUTH_CERT_DB_DATA), VariableName,
		NameSize * sizeof(UTF16));

	memcpy((uint8_t *)Ptr + sizeof(AUTH_CERT_DB_DATA) +
			NameSize * sizeof(UTF16),
		Sha256Digest, CertDataSize);

	//
	// Set "certdb" or "certdbv".
	//
	Status = AuthServiceInternalUpdateVariable(
		DbName, &gEfiCertDbGuid, NewCertDb, NewCertDbSize, VarAttr);

	return Status;
}

/**
  Clean up signer's certificates for common authenticated variable
  by corresponding VariableName and VendorGuid from "certdb".
  System may break down during Timebased Variable update & certdb update,
  make them inconsistent,  this function is called in AuthVariable Init
  to ensure consistency.

  @retval  EFI_NOT_FOUND         Fail to find variable "certdb".
  @retval  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @retval  EFI_SUCCESS           The operation is completed successfully.

**/
EFI_STATUS
CleanCertsFromDb(void)
{
	uint32_t Offset;
	AUTH_CERT_DB_DATA *Ptr;
	uint32_t NameSize;
	uint32_t NodeSize;
    uint32_t Attributes;
	UTF16 *VariableName;
	EFI_STATUS Status;
	bool CertCleaned;
	uint8_t *Data;
	uint64_t DataSize;
	EFI_GUID AuthVarGuid;

	Status = EFI_SUCCESS;

	//
	// Get corresponding certificates by VendorGuid and VariableName.
	//
	do {
		CertCleaned = false;

		//
		// Get latest variable "certdb"
		//
		Status = AuthServiceInternalFindVariable(
                             CERT_DB_NAME,
			     &gEfiCertDbGuid,
			     (void **)&Data,
			     &DataSize,
                             NULL);
		if (EFI_ERROR(Status)) {
			return Status;
		}

		if ((DataSize == 0) || (Data == NULL)) {
			assert(false);
			return EFI_NOT_FOUND;
		}

		Offset = sizeof(uint32_t);

		while (Offset < (uint32_t)DataSize) {
			Ptr = (AUTH_CERT_DB_DATA *)(Data + Offset);
			NodeSize = (uint32_t)Ptr->CertNodeSize;
			NameSize = (uint32_t)Ptr->NameSize;

			//
			// Get VarName tailed with '\0'
			//
			VariableName = malloc((NameSize + 1) *
							sizeof(UTF16));
			if (VariableName == NULL) {
				return EFI_OUT_OF_RESOURCES;
			}
			memcpy(VariableName,
				(uint8_t *)Ptr + sizeof(AUTH_CERT_DB_DATA),
				NameSize * sizeof(UTF16));
			//
			// Keep VarGuid  aligned
			//
			memcpy(&AuthVarGuid, &Ptr->VendorGuid,
				sizeof(EFI_GUID));

			//
			// Find corresponding time auth variable
			//
			Status = AuthServiceInternalFindVariable(
				VariableName, &AuthVarGuid, NULL, NULL, &Attributes);

			if (EFI_ERROR(Status) ||
			    (Attributes &
			     EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) ==
				    0) {
				Status = DeleteCertsFromDb(
					VariableName, &AuthVarGuid,
					Attributes);
				CertCleaned = true;
				DEBUG("Recovery!! Cert for Auth Variable is removed for consistency\n");
				free(VariableName);
				break;
			}

			free(VariableName);
			Offset = Offset + NodeSize;
		}
	} while (CertCleaned);

	return Status;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.
  @param[in]  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @param[in]  OrgTimeStamp                Pointer to original time stamp,
                                          original variable is not found if NULL.
  @param[out]  VarPayloadPtr              Pointer to variable payload address.
  @param[out]  VarPayloadSize             Pointer to variable payload size.

  @retval EFI_INVALID_PARAMETER           Invalid parameter.
  @retval EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifyTimeBasedPayload(UTF16 *VariableName, EFI_GUID *VendorGuid,
		       void *Data, uint64_t DataSize, uint32_t Attributes,
		       AUTHVAR_TYPE AuthVarType, EFI_TIME *OrgTimeStamp,
		       uint8_t **VarPayloadPtr, uint64_t *VarPayloadSize)
{
	EFI_VARIABLE_AUTHENTICATION_2 *DescriptorData;
	uint8_t *SigData;
	uint32_t SigDataSize;
	uint8_t *PayloadPtr;
	uint64_t PayloadSize;
	uint32_t Attr;
	bool VerifyStatus;
	EFI_STATUS Status;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert;
	uint64_t Index;
	uint64_t CertCount;
	uint32_t KekDataSize;
	uint8_t *NewData;
	uint64_t NewDataSize;
	uint8_t *Buffer;
	uint64_t Length;
	uint8_t *TopLevelCert;
	uint64_t TopLevelCertSize;
	uint8_t *TrustedCert;
	uint64_t TrustedCertSize;
	uint8_t *SignerCerts;
	uint64_t CertStackSize;
	uint8_t *CertsInCertDb;
	uint32_t CertsSizeinDb;
	uint8_t Sha256Digest[SHA256_DIGEST_SIZE];
	EFI_CERT_DATA *CertDataPtr;

	//
	// 1. TopLevelCert is the top-level issuer certificate in signature Signer Cert Chain
	// 2. TrustedCert is the certificate which firmware trusts. It could be saved in protected
	//     storage or PK payload on PK init
	//
	VerifyStatus = false;
	DescriptorData = NULL;
	NewData = NULL;
	Attr = Attributes;
	SignerCerts = NULL;
	TopLevelCert = NULL;
	CertsInCertDb = NULL;
	CertDataPtr = NULL;

	//
	// When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is
	// set, then the Data buffer shall begin with an instance of a complete (and serialized)
	// EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be followed by the new
	// variable value and DataSize shall reflect the combined size of the descriptor and the new
	// variable value. The authentication descriptor is not part of the variable data and is not
	// returned by subsequent calls to GetVariable().
	//
	DescriptorData = (EFI_VARIABLE_AUTHENTICATION_2 *)Data;

	//
	// Verify that Pad1, Nanosecond, TimeZone, Daylight and Pad2 components of the
	// TimeStamp value are set to zero.
	//
	if ((DescriptorData->TimeStamp.Pad1 != 0) ||
	    (DescriptorData->TimeStamp.Nanosecond != 0) ||
	    (DescriptorData->TimeStamp.TimeZone != 0) ||
	    (DescriptorData->TimeStamp.Daylight != 0) ||
	    (DescriptorData->TimeStamp.Pad2 != 0)) {
		return EFI_SECURITY_VIOLATION;
	}

	if ((OrgTimeStamp != NULL) &&
	    ((Attributes & EFI_VARIABLE_APPEND_WRITE) == 0)) {
		if (AuthServiceInternalCompareTimeStamp(&DescriptorData->TimeStamp,
							OrgTimeStamp)) {
			//
			// TimeStamp check fail, suspicious replay attack, return EFI_SECURITY_VIOLATION.
			//
			return EFI_SECURITY_VIOLATION;
		}
	}

	//
	// wCertificateType should be WIN_CERT_TYPE_EFI_GUID.
	// Cert type should be EFI_CERT_TYPE_PKCS7_GUID.
	//
	if ((DescriptorData->AuthInfo.Hdr.wCertificateType !=
	     WIN_CERT_TYPE_EFI_GUID) ||
	    !CompareGuid(&DescriptorData->AuthInfo.CertType, &gEfiCertPkcs7Guid)) {
		//
		// Invalid AuthInfo type, return EFI_SECURITY_VIOLATION.
		//
		return EFI_SECURITY_VIOLATION;
	}


	//
	// SigData is the DER-encoded Pkcs7 SignedData which follows the EFI_VARIABLE_AUTHENTICATION_2 descriptor.
	// AuthInfo.Hdr.dwLength is the length of the entire certificate, including the length of the header.
	//
	SigData = DescriptorData->AuthInfo.CertData;
	SigDataSize = DescriptorData->AuthInfo.Hdr.dwLength -
		      (uint32_t)(OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData));

    show("SigData", SigData, 32);

	//
	// SignedData.digestAlgorithms shall contain the digest algorithm used when preparing the
	// signature. Only a digest algorithm of SHA-256 is accepted.
	//
	//    According to PKCS#7 Definition:
	//        SignedData ::= SEQUENCE {
	//            version Version,
	//            digestAlgorithms DigestAlgorithmIdentifiers,
	//            contentInfo ContentInfo,
	//            .... }
	//    The DigestAlgorithmIdentifiers can be used to determine the hash algorithm
	//    in VARIABLE_AUTHENTICATION_2 descriptor.
	//    This field has the fixed offset (+13) and be calculated based on two bytes of length encoding.
	//
	if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) !=
	    0) {
		if (SigDataSize >= (13 + sizeof(mSha256OidValue))) {
			if (((*(SigData + 1) & TWO_BYTE_ENCODE) !=
			     TWO_BYTE_ENCODE) ||
			    (memcmp(SigData + 13, &mSha256OidValue,
					sizeof(mSha256OidValue)) != 0)) {
				return EFI_SECURITY_VIOLATION;
			}
		}
	}

	//
	// Find out the new data payload which follows Pkcs7 SignedData directly.
	//
	PayloadPtr = SigData + SigDataSize;
	PayloadSize =
		DataSize - OFFSET_OF_AUTHINFO2_CERT_DATA - (uint64_t)SigDataSize;

	//
	// Construct a serialization buffer of the values of the VariableName, VendorGuid and Attributes
	// parameters of the SetVariable() call and the TimeStamp component of the
	// EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable's new value
	// i.e. (VariableName, VendorGuid, Attributes, TimeStamp, Data)
	//
	NewDataSize = PayloadSize + sizeof(EFI_TIME) + sizeof(uint32_t) +
		      sizeof(EFI_GUID) + strsize16(VariableName) - sizeof(UTF16);

	//
	// Here is to reuse scratch data area(at the end of volatile variable store)
	// to reduce SMRAM consumption for SMM variable driver.
	// The scratch buffer is enough to hold the serialized data and safe to use,
	// because it is only used at here to do verification temporarily first
	// and then used in UpdateVariable() for a time based auth variable set.
	//
    NewData = malloc(NewDataSize);
	if ( !NewData ) {
		return EFI_OUT_OF_RESOURCES;
	}

	Buffer = NewData;
	Length = strlen16(VariableName) * sizeof(UTF16);
	memcpy(Buffer, VariableName, Length);
	Buffer += Length;

	Length = sizeof(EFI_GUID);
	memcpy(Buffer, VendorGuid, Length);
	Buffer += Length;

	Length = sizeof(uint32_t);
	memcpy(Buffer, &Attr, Length);
	Buffer += Length;

	Length = sizeof(EFI_TIME);
	memcpy(Buffer, &DescriptorData->TimeStamp, Length);
	Buffer += Length;

	memcpy(Buffer, PayloadPtr, PayloadSize);

	if (AuthVarType == AuthVarTypePk) {
        printf("%s:%d: SigDataSize=%lu\n", __func__, __LINE__, SigDataSize);
		//
		// Verify that the signature has been made with the current Platform Key (no chaining for PK).
		// First, get signer's certificates from SignedData.
		//
		VerifyStatus =
			Pkcs7GetSigners(SigData, SigDataSize, &SignerCerts,
					&CertStackSize, &TopLevelCert,
					&TopLevelCertSize);
		if (!VerifyStatus) {
			goto Exit;
		}

		//
		// Second, get the current platform key from variable. Check whether it's identical with signer's certificates
		// in SignedData. If not, return error immediately.
		//
		Status =
			AuthServiceInternalFindVariable(PK_NAME,
							&gEfiGlobalVariableGuid,
							&Data, &DataSize, NULL);
		if (EFI_ERROR(Status)) {
			VerifyStatus = false;
			goto Exit;
		}
		CertList = (EFI_SIGNATURE_LIST *)Data;
		Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)CertList +
					      sizeof(EFI_SIGNATURE_LIST) +
					      CertList->SignatureHeaderSize);
		if ((TopLevelCertSize != (CertList->SignatureSize -
					  (sizeof(EFI_SIGNATURE_DATA) - 1))) ||
		    (memcmp(Cert->SignatureData, TopLevelCert,
				TopLevelCertSize) != 0)) {
			VerifyStatus = false;
			goto Exit;
		}

		//
		// Verify Pkcs7 SignedData via Pkcs7Verify library.
		//
		VerifyStatus =
			Pkcs7Verify(SigData, SigDataSize, TopLevelCert,
				    TopLevelCertSize, NewData, NewDataSize);

	} else if (AuthVarType == AuthVarTypeKek) {
		//
		// Get KEK database from variable.
		//
		Status = AuthServiceInternalFindVariable(
			KEK_NAME, &gEfiGlobalVariableGuid,
			&Data, &DataSize, NULL);
		if (EFI_ERROR(Status)) {
			return Status;
		}

		//
		// Ready to verify Pkcs7 SignedData. Go through KEK Signature Database to find out X.509 CertList.
		//
		KekDataSize = (uint32_t)DataSize;
		CertList = (EFI_SIGNATURE_LIST *)Data;
		while ((KekDataSize > 0) &&
		       (KekDataSize >= CertList->SignatureListSize)) {
			if (CompareGuid(&CertList->SignatureType,
					&gEfiCertX509Guid)) {
				Cert = (EFI_SIGNATURE_DATA
						*)((uint8_t *)CertList +
						   sizeof(EFI_SIGNATURE_LIST) +
						   CertList->SignatureHeaderSize);
				CertCount = (CertList->SignatureListSize -
					     sizeof(EFI_SIGNATURE_LIST) -
					     CertList->SignatureHeaderSize) /
					    CertList->SignatureSize;
				for (Index = 0; Index < CertCount; Index++) {
					//
					// Iterate each Signature Data Node within this CertList for a verify
					//
					TrustedCert = Cert->SignatureData;
					TrustedCertSize =
						CertList->SignatureSize -
						(sizeof(EFI_SIGNATURE_DATA) -
						 1);

					//
					// Verify Pkcs7 SignedData via Pkcs7Verify library.
					//
					VerifyStatus = Pkcs7Verify(
						SigData, SigDataSize,
						TrustedCert, TrustedCertSize,
						NewData, NewDataSize);
					if (VerifyStatus) {
						goto Exit;
					}
					Cert = (EFI_SIGNATURE_DATA
							*)((uint8_t *)Cert +
							   CertList->SignatureSize);
				}
			}
			KekDataSize -= CertList->SignatureListSize;
			CertList = (EFI_SIGNATURE_LIST
					    *)((uint8_t *)CertList +
					       CertList->SignatureListSize);
		}
	} else if (AuthVarType == AuthVarTypePriv) {
		//
		// Process common authenticated variable except PK/KEK/DB/DBX/DBT.
		// Get signer's certificates from SignedData.
		//
		VerifyStatus =
			Pkcs7GetSigners(SigData, SigDataSize, &SignerCerts,
					&CertStackSize, &TopLevelCert,
					&TopLevelCertSize);
		if (!VerifyStatus) {
			goto Exit;
		}

		//
		// Get previously stored signer's certificates from certdb or certdbv for existing
		// variable. Check whether they are identical with signer's certificates
		// in SignedData. If not, return error immediately.
		//
		if (OrgTimeStamp != NULL) {
			VerifyStatus = false;

			Status = GetCertsFromDb(VariableName, VendorGuid,
						Attributes, &CertsInCertDb,
						&CertsSizeinDb);
			if (EFI_ERROR(Status)) {
				goto Exit;
			}

			if (CertsSizeinDb == SHA256_DIGEST_SIZE) {
				//
				// Check hash of signer cert CommonName + Top-level issuer tbsCertificate against data in CertDb
				//
				CertDataPtr =
					(EFI_CERT_DATA *)(SignerCerts + 1);
				Status = CalculatePrivAuthVarSignChainSHA256Digest(
					CertDataPtr->CertDataBuffer,
					*((uint32_t *)&(
						CertDataPtr->CertDataLength)),
					TopLevelCert, TopLevelCertSize,
					Sha256Digest);
				if (EFI_ERROR(Status) ||
				    memcmp(Sha256Digest, CertsInCertDb,
					       CertsSizeinDb) != 0)
                {
					goto Exit;
				}
			}
            else
            {
				//
				// Keep backward compatible with previous solution which saves whole signer certs stack in CertDb
				//
				if ((CertStackSize != CertsSizeinDb) ||
				    (memcmp(SignerCerts, CertsInCertDb,
						CertsSizeinDb) != 0)) {
					goto Exit;
				}
			}
		}

		VerifyStatus =
			Pkcs7Verify(SigData, SigDataSize, TopLevelCert,
				    TopLevelCertSize, NewData, NewDataSize);
		if (!VerifyStatus) {
			goto Exit;
		}

		if ((OrgTimeStamp == NULL) && (PayloadSize != 0)) {
			//
			// When adding a new common authenticated variable, always save Hash of cn of signer cert + tbsCertificate of Top-level issuer
			//
			CertDataPtr = (EFI_CERT_DATA *)(SignerCerts + 1);
			Status = InsertCertsToDb(
				VariableName, VendorGuid, Attributes,
				CertDataPtr->CertDataBuffer,
				*((uint64_t *)&(
					CertDataPtr->CertDataLength)),
				TopLevelCert, TopLevelCertSize);
			if (EFI_ERROR(Status)) {
				VerifyStatus = false;
				goto Exit;
			}
		}
	} else if (AuthVarType == AuthVarTypePayload) {
		CertList = (EFI_SIGNATURE_LIST *)PayloadPtr;
		Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)CertList +
					      sizeof(EFI_SIGNATURE_LIST) +
					      CertList->SignatureHeaderSize);
		TrustedCert = Cert->SignatureData;
		TrustedCertSize = CertList->SignatureSize -
				  (sizeof(EFI_SIGNATURE_DATA) - 1);
		//
		// Verify Pkcs7 SignedData via Pkcs7Verify library.
		//
		VerifyStatus =
			Pkcs7Verify(SigData, SigDataSize, TrustedCert,
				    TrustedCertSize, NewData, NewDataSize);
	} else {
		return EFI_SECURITY_VIOLATION;
	}

Exit:

	if (AuthVarType == AuthVarTypePk || AuthVarType == AuthVarTypePriv) {
		Pkcs7FreeSigners(TopLevelCert);
		Pkcs7FreeSigners(SignerCerts);
	}

	if (!VerifyStatus) {
		return EFI_SECURITY_VIOLATION;
	}

	Status = CheckSignatureListFormat(VariableName, VendorGuid, PayloadPtr,
					  PayloadSize);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	*VarPayloadPtr = PayloadPtr;
	*VarPayloadSize = PayloadSize;

	return EFI_SUCCESS;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.
  @param[in]  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @param[out] VarDel                      Delete the variable or not.

  @retval EFI_INVALID_PARAMETER           Invalid parameter.
  @retval EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifyTimeBasedPayloadAndUpdate(UTF16 *VariableName,
				EFI_GUID *VendorGuid, void *Data,
				uint64_t DataSize, uint32_t Attributes,
				AUTHVAR_TYPE AuthVarType,
				bool *VarDel)
{
    EFI_TIME *TimeStamp;
	EFI_STATUS Status;
	EFI_STATUS FindStatus;
	uint8_t *PayloadPtr;
	uint64_t PayloadSize;
	EFI_VARIABLE_AUTHENTICATION_2 *CertData;
	AUTH_VARIABLE_INFO OrgVariableInfo;
	bool IsDel;
    size_t len;
    void *OldData;
    size_t *OldDataSize;
    
    /* Retrieve data for variable */
	FindStatus = AuthServiceInternalFindVariable(
		VariableName, VendorGuid, &OldData, &OldDataSize, NULL);

    if ( EFI_ERROR(FindStatus) )
    {
        return FindStatus;
    }

	memset(&OrgVariableInfo, 0, sizeof(OrgVariableInfo));

    TimeStamp = to_timestamp(OldData, OldDataSize);

    if ( !TimeStamp )
    {
        DEBUG("%s: could not find timestamp in varstore\n", __func__);
    }

    OrgVariableInfo.TimeStamp = TimeStamp;

	Status = VerifyTimeBasedPayload(
		VariableName, VendorGuid, Data, DataSize, Attributes,
		AuthVarType,
		TimeStamp,
		&PayloadPtr, &PayloadSize);

	if ( Status ) {
		return Status;
	}

	if (!EFI_ERROR(FindStatus) && (PayloadSize == 0) &&
	    ((Attributes & EFI_VARIABLE_APPEND_WRITE) == 0)) {
		IsDel = true;
	} else {
		IsDel = false;
	}

	CertData = (EFI_VARIABLE_AUTHENTICATION_2 *)Data;

	//
	// Final step: Update/Append Variable if it pass Pkcs7Verify
	//
	Status = AuthServiceInternalUpdateVariableWithTimeStamp(
		VariableName, VendorGuid, PayloadPtr, PayloadSize, Attributes,
		&CertData->TimeStamp);

	//
	// Delete signer's certificates when delete the common authenticated variable.
	//
	if (IsDel && AuthVarType == AuthVarTypePriv && !EFI_ERROR(Status)) {
		Status =
			DeleteCertsFromDb(VariableName, VendorGuid, Attributes);
	}

	if (VarDel != NULL) {
		if (IsDel && !EFI_ERROR(Status)) {
			*VarDel = true;
		} else {
			*VarDel = false;
		}
	}

	return Status;
}
