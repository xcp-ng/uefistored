#include <stdio.h>

#include "crypt/pkcs7_signed_data.h"
#include "uefitypes.h"
#include "uefi_guids.h"
#include "test_common.h"
#include "test_crypt.h"
#include "src/edk2/secure_boot.h"

static UTF16 name[] = {'F', 'o', 'o', 0 };
static UTF16 data[] = {'B', 'a', 'r', 0 };

#if 0
EFI_STATUS GetTime (EFI_TIME *Time, uint8_t seconds)
{
    Time->Year = 1990;
    Time->Month = 12;
    Time->Day = 25;
    Time->Hour = 12;
    Time->Minute = 12;
    Time->Second = seconds;
    Time->Pad1 = 0;
    Time->Nanosecond = 0;
    Time->TimeZone = 0;
    Time->Daylight = 0;
    Time->Pad2 = 0;

    return EFI_SUCCESS;
}
#endif


int test_crypt(void)
{
    int ret;
    EVP_PKEY *pkey = NULL;
    EFI_GUID guid = gEfiGlobalVariableGuid;
    EFI_GUID pkcs7 = EFI_CERT_TYPE_PKCS7_GUID;
    EFI_TIME timestamp;
    EFI_VARIABLE_AUTHENTICATION_2 descriptor;
    uint8_t *concatenated, *p;
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    size_t namesz, datasz;
	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

    GetTime(&descriptor.TimeStamp, 0);
    memcpy(&descriptor.AuthInfo.CertType, &pkcs7, sizeof(EFI_GUID));

    namesz = sizeof(name);
    datasz = sizeof(data);

    concatenated = malloc(namesz + datasz +
                          sizeof(EFI_GUID) +
                          sizeof(attributes) +
                          sizeof(EFI_TIME));
                          
    p = concatenated;
    memcpy(p, name, namesz);
    p += namesz;
    memcpy(p, &guid, sizeof(EFI_GUID));
    p += sizeof(EFI_GUID);
    memcpy(p, &attributes, sizeof(attributes));
    p += sizeof(attributes);
    memcpy(p, &descriptor.TimeStamp, sizeof(EFI_TIME));
    p += sizeof(EFI_TIME);
    memcpy(p, data, datasz);
    p += datasz;

    sha256_hash(hash, concatenated);

    pkey = get_rsa_key();
    if ( !pkey )
    {
        fprintf(stderr, "No key!\n");
        return -1;
    }

    uint8_t buf[] = { 0, 1, 2, 3 };
    uint8_t *signed_data;
    uint32_t signed_data_size;
    uint8_t *sign_cert;
    ret = pkcs7_sign(buf, sizeof(buf), sign_cert, NULL, &signed_data, &signed_data_size);
    printf("%s:%d, pkcs7_sign=%d\n", __func__, __LINE__, ret);

    int i;
    for ( i=0; i<16; i++ )
        printf("0x%02x ", buf[i]);
    printf("\n");

    printf("%s:%d\n", __func__, __LINE__);
    free(concatenated);
    printf("%s:%d\n", __func__, __LINE__);

    return 0;
}
