#ifndef __H_UEFITYPES_
#define __H_UEFITYPES_

#include <stdint.h>

#define EFI_MAX_BIT       0x8000000000000000UL
#define EFIERR(a)         (EFI_MAX_BIT | (a))

typedef struct {
    uint8_t guid[16];
} EFI_GUID;

typedef uint64_t EFI_STATUS;
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER EFIERR(2)
#define EFI_BUFFER_TOO_SMALL EFIERR(5)
#define EFI_DEVICE_ERROR EFIERR(7)
#define EFI_OUT_OF_RESOURCES EFIERR(9)
#define EFI_NOT_FOUND EFIERR(14)
#define EFI_SECURITY_VIOLATION EFIERR(26)

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
