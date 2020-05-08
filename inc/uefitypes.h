#ifndef __H_UEFITYPES_
#define __H_UEFITYPES_

#include <stdint.h>

typedef struct {
    uint8_t guid[16];
} EFI_GUID;

typedef uint64_t EFI_STATUS;
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 2
#define EFI_BUFFER_TOO_SMALL 5
#define EFI_DEVICE_ERROR 7
#define EFI_OUT_OF_RESOURCES 9
#define EFI_NOT_FOUND 14
#define EFI_SECURITY_VIOLATION 26

typedef struct {
    uint32_t  data1;
    uint16_t  data2;
    uint16_t  data3;
    uint8_t   data4[8];
} efi_guid_t;


typedef enum command {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
    COMMAND_NOTIFY_SB_FAILURE,
} command_t;

#endif // __H_UEFITYPES_
