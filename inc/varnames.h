#ifndef __H_VAR_NAMES_
#define __H_VAR_NAMES_

#include "uefitypes.h"

extern UTF16 KEK_NAME[];
extern UTF16 PK_NAME[];
extern UTF16 CERT_DB_NAME[];
extern UTF16 CERT_DBV_NAME[];
extern UTF16 VENDOR_KEYS_NAME[];

extern UTF16 CUSTOM_MODE_NAME[];
#define CUSTOM_SECURE_BOOT_MODE       1
#define STANDARD_SECURE_BOOT_MODE     0

extern UTF16 VENDOR_KEYS_NV_NAME[];
#define VENDOR_KEYS_VALID             1
#define VENDOR_KEYS_MODIFIED          0

extern UTF16 SECURE_BOOT_ENABLE_NAME[];
#define SECURE_BOOT_ENABLE               1
#define SECURE_BOOT_DISABLE              0

extern UTF16 SECURE_BOOT_NAME[];
#define SECURE_BOOT_MODE_ENABLE           1
#define SECURE_BOOT_MODE_DISABLE          0

extern UTF16 SECURE_BOOT_MODE_NAME[];

extern UTF16 SETUP_MODE_NAME[];
#define SETUP_MODE                        1
#define USER_MODE                         0

extern UTF16 DB_NAME[];
extern UTF16 DBX_NAME[];
extern UTF16 DBT_NAME[];


#endif // __H_VAR_NAMES_