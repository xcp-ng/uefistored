#include "uefitypes.h"

EFI_GUID gEfiCertPkcs7Guid = { 0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7 }};

EFI_GUID gEfiGlobalVariableGuid = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }};

EFI_GUID gEfiCertX509Guid = { 0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 }};

EFI_GUID gEfiCertDbGuid = { 0xd9bee56e, 0x75dc, 0x49d9, { 0xb4, 0xd7, 0xb5, 0x34, 0x21, 0xf, 0x63, 0x7a }};

EFI GUID gEfiVendorKeysNvGuid = { 0x9073e4e0, 0x60ec, 0x4b6e, { 0x99, 0x3, 0x4c, 0x22, 0x3c, 0x26, 0xf, 0x3c } }

UTF16 SetupMode[] = {'S', 'e', 't', 'u', 'p', 'M', 'o', 'd', 'e', '\0'};
UTF16 KEK[] = {'K', 'E', 'K', '\0'};
UTF16 PK[] = {'P', 'K', '\0'};
UTF16 CERT_DB[] = {'c', 'e', 'r', 't', 'd', 'b', '\0'};
UTF16 CERT_DBV[] = {'c', 'e', 'r', 't', 'd', 'b', 'v', '\0'};
UTF16 VENDOR_KEYS[] = {'V', 'e', 'n', 'd', 'o', 'r', 'K', 'e', 'y', 's', '\0'};
UTF16 VENDOR_KEYS_NV[] = {'V', 'e', 'n', 'd', 'o', 'r', 'K', 'e', 'y', 's', 'N', 'v', '\0'};
UTF16 SECURE_BOOT_ENABLE[] = {'S', 'e', 'c', 'u', 'r', 'e',
				'B', 'o', 'o', 't',
				'E', 'n', 'a', 'b', 'l', 'e'};
