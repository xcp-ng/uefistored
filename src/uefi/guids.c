#include "uefi/types.h"
#include "uefi/guids.h"

// Guids
EFI_GUID gEfiGlobalVariableGuid = EFI_GLOBAL_VARIABLE_GUID;

EFI_GUID gShimLockGuid = { 0x605dab50,
                           0xe046,
                           0x4300,
                           { 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } };

EFI_GUID gEfiCertDbGuid = { 0xd9bee56e,
                            0x75dc,
                            0x49d9,
                            { 0xb4, 0xd7, 0xb5, 0x34, 0x21, 0xf, 0x63, 0x7a } };

EFI_GUID gEfiVendorKeysNvGuid = { 0x9073e4e0,
                                  0x60ec,
                                  0x4b6e,
                                  { 0x99, 0x3, 0x4c, 0x22, 0x3c, 0x26, 0xf,
                                    0x3c } };

EFI_GUID gEfiFileInfoGuid = { 0x09576E92,
                              0x6D3F,
                              0x11D2,
                              { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72,
                                0x3B } };

EFI_GUID gEfiImageSecurityDatabaseGuid = { 0xd719b2cb,
                                           0x3d3a,
                                           0x4596,
                                           { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67,
                                             0x65, 0x6f } };
EFI_GUID gEfiCertX509Guid = { 0xa5c059a1,
                              0x94e4,
                              0x4aa7,
                              { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0,
                                0x72 } };

EFI_GUID gEfiCertPkcs7Guid = { 0x4aafd29d,
                               0x68df,
                               0x49ee,
                               { 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65,
                                 0xa7 } };

EFI_GUID gEfiSecureBootEnableDisableGuid = { 0xf0a30bc7,
                                             0xaf08,
                                             0x4556,
                                             { 0x99, 0xc4, 0x0, 0x10, 0x9, 0xc9,
                                               0x3a, 0x44 } };

EFI_GUID gEfiCustomModeEnableGuid = { 0xc076ec0c,
                                      0x7028,
                                      0x4399,
                                      { 0xa0, 0x72, 0x71, 0xee, 0x5c, 0x44,
                                        0x8b, 0x9f } };
