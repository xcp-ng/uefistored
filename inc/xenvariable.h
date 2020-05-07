#ifndef __H_XENVARIABLE_
#define __H_XENVARIABLE_

#include <stdint.h>

/* UEFI Definitions */
typedef uint64_t EFI_STATUS;
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 2
#define EFI_BUFFER_TOO_SMALL 5
#define EFI_DEVICE_ERROR 7
#define EFI_NOT_FOUND 14
#define EFI_SECURITY_VIOLATION 26

typedef struct {
    uint32_t  data1;
    uint16_t  data2;
    uint16_t  data3;
    uint8_t   data4[8];
} efi_guid_t;

void xenvariable_handle_request(void *comm_buff);

#endif // __H_XENVARIABLE_
