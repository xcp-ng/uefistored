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

#endif // __H_AUTH_SERVICE_H
