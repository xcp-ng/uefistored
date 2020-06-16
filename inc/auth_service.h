#ifndef __H_AUTH_SERVICE_H
#define __H_AUTH_SERVICE_H

#include <stdint.h>
#include "uefitypes.h"

EFI_STATUS
AuthServiceInternalUpdateVariableWithTimeStamp(
                           UTF16 *VariableName,
					       EFI_GUID *VendorGuid,
					       void *Data, uint64_t DataSize,
					       uint32_t Attributes,
					       EFI_TIME *TimeStamp);

EFI_STATUS
VerifyTimeBasedPayloadAndUpdate(
                UTF16 *VariableName,
				EFI_GUID *VendorGuid,
                void *Data,
				uint64_t DataSize,
                uint32_t Attributes,
				AUTHVAR_TYPE AuthVarType,
				bool *VarDel);

EFI_STATUS
VerifyTimeBasedPayload(UTF16 *VariableName, EFI_GUID *VendorGuid,
		       void *Data, uint64_t DataSize, uint32_t Attributes,
		       AUTHVAR_TYPE AuthVarType, EFI_TIME *OrgTimeStamp,
		       uint8_t **VarPayloadPtr, uint64_t *VarPayloadSize);

EFI_STATUS
AuthServiceInternalFindVariable(UTF16 *VariableName,
				const EFI_GUID *VendorGuid, void **Data,
				uint64_t *DataSize, 
                uint32_t *attrs);

EFI_STATUS
InsertCertsToDb(UTF16 *VariableName, EFI_GUID *VendorGuid,
		uint32_t Attributes, uint8_t *SignerCert,
		uint64_t SignerCertSize, uint8_t *TopLevelCert,
		uint64_t TopLevelCertSize);

EFI_STATUS
GetCertsFromDb(UTF16 *VariableName, EFI_GUID *VendorGuid,
	       uint32_t Attributes, uint8_t **CertData,
	       uint32_t *CertDataSize);

EFI_STATUS
CheckSignatureListFormat(UTF16 *VariableName, EFI_GUID *VendorGuid,
			 void *Data, uint64_t DataSize);

EFI_STATUS
CalculatePrivAuthVarSignChainSHA256Digest(uint8_t *SignerCert,
					  uint64_t SignerCertSize,
					  uint8_t *TopLevelCert,
					  uint64_t TopLevelCertSize,
					  uint8_t *Sha256Digest);

#endif // __H_AUTH_SERVICE_H
