#include "uefi/types.h"

EFI_GUID gShimLockGuid = {0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } };

EFI_GUID gEfiCertDbGuid = { 0xd9bee56e,
                            0x75dc,
                            0x49d9,
                            { 0xb4, 0xd7, 0xb5, 0x34, 0x21, 0xf, 0x63, 0x7a } };

EFI_GUID gEfiVendorKeysNvGuid = { 0x9073e4e0,
                                  0x60ec,
                                  0x4b6e,
                                  { 0x99, 0x3, 0x4c, 0x22, 0x3c, 0x26, 0xf,
                                    0x3c } };

// Guids
EFI_GUID gEfiEndOfDxeEventGroupGuid = { 0x2ce967a,
                                        0xdd7e,
                                        0x4ffc,
                                        { 0x9e, 0xe7, 0x81, 0xc, 0xf0, 0x47,
                                          0x8, 0x80 } };
EFI_GUID gEfiMdePkgTokenSpaceGuid = { 0x914AEBE7,
                                      0x4635,
                                      0x459b,
                                      { 0xAA, 0x1C, 0x11, 0xE2, 0x19, 0xB0,
                                        0x3A, 0x10 } };
EFI_GUID gUefiOvmfPkgTokenSpaceGuid = { 0x93bb96af,
                                        0xb9f2,
                                        0x4eb8,
                                        { 0x94, 0x62, 0xe0, 0xba, 0x74, 0x56,
                                          0x42, 0x36 } };
EFI_GUID gEfiEventReadyToBootGuid = { 0x7CE88FB3,
                                      0x4BD7,
                                      0x4679,
                                      { 0x87, 0xA8, 0xA8, 0xD8, 0xDE, 0xE5,
                                        0x0D, 0x2B } };
EFI_GUID gEfiEventLegacyBootGuid = { 0x2A571201,
                                     0x4966,
                                     0x47F6,
                                     { 0x8B, 0x86, 0xF3, 0x1E, 0x41, 0xF3, 0x2F,
                                       0x10 } };
EFI_GUID gEfiGlobalVariableGuid = { 0x8BE4DF61,
                                    0x93CA,
                                    0x11D2,
                                    { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B,
                                      0x8C } };
EFI_GUID gEfiFileInfoGuid = { 0x09576E92,
                              0x6D3F,
                              0x11D2,
                              { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72,
                                0x3B } };
EFI_GUID gEfiStatusCodeSpecificDataGuid = { 0x335984BD,
                                            0xE805,
                                            0x409A,
                                            { 0xB8, 0xF8, 0xD2, 0x7E, 0xCE,
                                              0x5F, 0xF7, 0xA6 } };
EFI_GUID gEfiStatusCodeDataTypeDebugGuid = { 0x9A4E9246,
                                             0xD553,
                                             0x11D5,
                                             { 0x87, 0xE2, 0x00, 0x06, 0x29,
                                               0x45, 0xC3, 0xB9 } };
EFI_GUID gEfiImageSecurityDatabaseGuid = { 0xd719b2cb,
                                           0x3d3a,
                                           0x4596,
                                           { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67,
                                             0x65, 0x6f } };
EFI_GUID gEfiCertSha1Guid = { 0x826ca512,
                              0xcf10,
                              0x4ac9,
                              { 0xb1, 0x87, 0xbe, 0x1, 0x49, 0x66, 0x31,
                                0xbd } };
EFI_GUID gEfiCertSha256Guid = { 0xc1c41626,
                                0x504c,
                                0x4092,
                                { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43,
                                  0x28 } };
EFI_GUID gEfiCertSha384Guid = { 0xff3e5307,
                                0x9fd0,
                                0x48c9,
                                { 0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e,
                                  0x1 } };
EFI_GUID gEfiCertSha512Guid = { 0x93e0fae,
                                0xa6c4,
                                0x4f50,
                                { 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1,
                                  0x9a } };
EFI_GUID gEfiCertX509Guid = { 0xa5c059a1,
                              0x94e4,
                              0x4aa7,
                              { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0,
                                0x72 } };
EFI_GUID gEfiCertX509Sha256Guid = { 0x3bd2a492,
                                    0x96c0,
                                    0x4079,
                                    { 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03,
                                      0xed } };
EFI_GUID gEfiCertX509Sha384Guid = { 0x7076876e,
                                    0x80c2,
                                    0x4ee6,
                                    { 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86,
                                      0x5b } };
EFI_GUID gEfiCertX509Sha512Guid = { 0x446dbf63,
                                    0x2502,
                                    0x4cda,
                                    { 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe,
                                      0x9d } };
EFI_GUID gEfiCertPkcs7Guid = { 0x4aafd29d,
                               0x68df,
                               0x49ee,
                               { 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65,
                                 0xa7 } };
EFI_GUID gEfiSecurityPkgTokenSpaceGuid = { 0xd3fb176,
                                           0x9569,
                                           0x4d51,
                                           { 0xa3, 0xef, 0x7d, 0x61, 0xc6, 0x4f,
                                             0xea, 0xba } };
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
