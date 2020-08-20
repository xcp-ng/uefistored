#include "uefi/types.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void _show(const char *func, const char *string, void *data, size_t n)
{
    size_t i;
    uint16_t *p = data;

    printf("%s:%s", func, string);
    for (i = 0; i < n; i++) {
        if (i % 8 == 0)
            printf("\n");
        printf("0x%04x ", p[i]);
    }
    printf("\n\n");
}

#define show(string, data, n) _show(__func__, string, data, n)

static UTF16 EFI_PLATFORM_KEY_NAME[] = { 'P', 'K', 0 };

extern EFI_STATUS set_variable(void *variable, EFI_GUID *guid, uint32_t attrs,
                               size_t datasz, void *data);

extern const EFI_GUID gEfiCertPkcs7Guid;
extern const EFI_GUID gEfiCertX509Guid;
extern const EFI_GUID gEfiGlobalVariableGuid;

EFI_STATUS GetTime(EFI_TIME *Time, uint8_t seconds)
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

EFI_STATUS ReadFileContent(const char *file, void **data, uint64_t *datasize)
{
    uint8_t buf[4096];
    ssize_t len;
    int fd;

    fd = open(file, O_RDONLY);

    if (fd < 0)
        return EFI_NOT_FOUND;

    len = read(fd, buf, 4096);

    if (len < 0)
        return EFI_DEVICE_ERROR;

    *data = malloc(len);
    memcpy(*data, buf, len);

    *datasize = (uint64_t)len;

    return EFI_SUCCESS;
}

/**
  Create a time based data payload by concatenating the EFI_VARIABLE_AUTHENTICATION_2
  descriptor with the input data. NO authentication is required in this function.

  @param[in, out] DataSize          On input, the size of Data buffer in bytes.
                                    On output, the size of data returned in Data
                                    buffer in bytes.
  @param[in, out] Data              On input, Pointer to data buffer to be wrapped or
                                    pointer to NULL to wrap an empty payload.
                                    On output, Pointer to the new payload date buffer allocated from pool,
                                    it's caller's responsibility to free the memory after using it.

  @retval EFI_SUCCESS               Create time based payload successfully.
  @retval EFI_OUT_OF_RESOURCES      There are not enough memory resourses to create time based payload.
  @retval EFI_INVALID_PARAMETER     The parameter is invalid.
  @retval Others                    Unexpected error happens.

**/
EFI_STATUS
CreateTimeBasedPayload(uint64_t *DataSize, uint8_t **Data,
                       EFI_GUID *CertTypeGuid, uint8_t seconds,
                       uint64_t SigDataSize)
{
    EFI_STATUS Status;
    uint8_t *NewData;
    uint8_t *Payload;
    uint64_t PayloadSize;
    EFI_VARIABLE_AUTHENTICATION_2 *DescriptorData;
    uint64_t DescriptorSize;
    EFI_TIME Time;

    if (Data == NULL || DataSize == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    //
    // At user physical presence, the variable does not need to be signed but the
    // parameters to the SetVariable() call still need to be prepared as authenticated
    // variable. So we create EFI_VARIABLE_AUTHENTICATED_2 descriptor without certificate
    // data in it.
    //
    Payload = *Data;
    PayloadSize = *DataSize;
    printf("%s: ds=%lu\n", __func__, *DataSize);

    DescriptorSize = OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) +
                     OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
    NewData = (uint8_t *)malloc(DescriptorSize + PayloadSize);
    if (NewData == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    if ((Payload != NULL) && (PayloadSize != 0)) {
        memcpy(NewData + DescriptorSize, Payload, PayloadSize);
    }

    DescriptorData = (EFI_VARIABLE_AUTHENTICATION_2 *)(NewData);

    memset(&Time, 0, sizeof(EFI_TIME));
    Status = GetTime(&Time, seconds);
    if (EFI_ERROR(Status)) {
        free(NewData);
        return Status;
    }
    Time.Pad1 = 0;
    Time.Nanosecond = 0;
    Time.TimeZone = 0;
    Time.Daylight = 0;
    Time.Pad2 = 0;
    memcpy(&DescriptorData->TimeStamp, &Time, sizeof(EFI_TIME));

    DescriptorData->AuthInfo.Hdr.dwLength =
            OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData) + SigDataSize;
    DescriptorData->AuthInfo.Hdr.wRevision = 0x0200;
    DescriptorData->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
    memcpy(&DescriptorData->AuthInfo.CertType, CertTypeGuid, sizeof(EFI_GUID));

    if (Payload != NULL) {
        free(Payload);
    }

    *DataSize = DescriptorSize + PayloadSize;
    *Data = NewData;

    printf("dwLength=%u, off=0x%02lx\n", DescriptorData->AuthInfo.Hdr.dwLength,
           ((uint64_t)&DescriptorData->AuthInfo.Hdr.dwLength) -
                   ((uint64_t)(DescriptorData)));

    uint8_t *SigData = DescriptorData->AuthInfo.CertData;
    show("SigData", SigData, 32);
    printf("%s: SigDataSize=%lu\n", __func__, SigDataSize);
    printf("%s: DataSize=%lu\n", __func__, *DataSize);
    printf("%s: OFF_OF=%lu\n", __func__,
           (OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData)));

    return EFI_SUCCESS;
}

/**
  Generate the PK signature list from the X509 Certificate storing file (.cer)

  @param[in]   X509File              FileHandle of X509 Certificate storing file.
  @param[out]  PkCert                Point to the data buffer to store the signature list.

  @return EFI_UNSUPPORTED            Unsupported Key Length.
  @return EFI_OUT_OF_RESOURCES       There are not enough memory resourses to form the signature list.

**/
EFI_STATUS
CreatePkX509SignatureList(const char *X509File, EFI_SIGNATURE_LIST **PkCert,
                          uint64_t *X509SizeOut)
{
    EFI_STATUS Status;
    uint8_t *X509Data;
    uint64_t X509DataSize;
    EFI_SIGNATURE_DATA *PkCertData;

    X509Data = NULL;
    PkCertData = NULL;
    X509DataSize = 0;

    Status = ReadFileContent(X509File, (void **)&X509Data, &X509DataSize);
    if (EFI_ERROR(Status)) {
        goto ON_EXIT;
    }
    assert(X509Data != NULL);
    *X509SizeOut = X509DataSize;

    show("X509Data", X509Data, 32);

    //
    // Allocate space for PK certificate list and initialize it.
    // Create PK database entry with SignatureHeaderSize equals 0.
    //
    *PkCert = (EFI_SIGNATURE_LIST *)malloc(sizeof(EFI_SIGNATURE_LIST) +
                                           sizeof(EFI_SIGNATURE_DATA) - 1 +
                                           X509DataSize);
    if (*PkCert == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
    }

    (*PkCert)->SignatureListSize =
            (uint32_t)(sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) -
                       1 + X509DataSize);
    (*PkCert)->SignatureSize =
            (uint32_t)(sizeof(EFI_SIGNATURE_DATA) - 1 + X509DataSize);
    (*PkCert)->SignatureHeaderSize = 0;
    memcpy(&(*PkCert)->SignatureType, &gEfiCertX509Guid, sizeof(EFI_GUID));
    PkCertData = (EFI_SIGNATURE_DATA *)((uint64_t)(*PkCert) +
                                        sizeof(EFI_SIGNATURE_LIST) +
                                        (*PkCert)->SignatureHeaderSize);
    memcpy(&PkCertData->SignatureOwner, &gEfiGlobalVariableGuid,
           sizeof(EFI_GUID));
    //
    // Fill the PK database with PKpub data from X509 certificate file.
    //
    memcpy(&(PkCertData->SignatureData[0]), X509Data, X509DataSize);

    printf("(*PkCert)->SignatureSize=%u\n", (*PkCert)->SignatureSize);
    show("*PkCert", *PkCert, 32);

ON_EXIT:

    if (X509Data != NULL) {
        free(X509Data);
    }

    if (EFI_ERROR(Status) && *PkCert != NULL) {
        free(*PkCert);
        *PkCert = NULL;
    }

    //  EFI_SIGNATURE_LIST *pkcert_list = *PkCert;
    //  EFI_SIGNATURE_DATA *pkcert_data = PkCertData;

    return Status;
}

/**
  Enroll new PK into the System without original PK's authentication.

  The SignatureOwner GUID will be the same with PK's vendorguid.
  @retval   EFI_SUCCESS            New PK enrolled successfully.
  @retval   EFI_INVALID_PARAMETER  The parameter is invalid.
  @retval   EFI_OUT_OF_RESOURCES   Could not allocate needed resources.

**/
EFI_STATUS
EnrollPlatformKey(EFI_GUID *VariableGuid, EFI_GUID *CertTypeGuid,
                  char *FileName, uint8_t seconds)
{
    EFI_STATUS Status;
    uint32_t Attr;
    uint64_t DataSize;
    EFI_SIGNATURE_LIST *PkCert;
    uint64_t NameLength;
    uint64_t SigDataSize;

    if (FileName == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    PkCert = NULL;

#if 0
  Status = SetSecureBootMode(CUSTOM_SECURE_BOOT_MODE);
  if (EFI_ERROR (Status)) {
    return Status;
  }
#endif

    //
    // Parse the file's postfix. Only support DER encoded X.509 certificate files.
    //
    NameLength = strlen(FileName);
    if (NameLength <= 4) {
        return EFI_INVALID_PARAMETER;
    }
    //
    // Parse the selected PK file and generature PK certificate list.
    //
    Status = CreatePkX509SignatureList(FileName, &PkCert, &SigDataSize);
    if (Status) {
        goto ON_EXIT;
    }
    assert(PkCert != NULL);

    //
    // Set Platform Key variable.
    //
    Attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
           EFI_VARIABLE_BOOTSERVICE_ACCESS |
           EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    DataSize = PkCert->SignatureListSize;
    Status = CreateTimeBasedPayload(&DataSize, (uint8_t **)&PkCert,
                                    CertTypeGuid, seconds, 0);
    if (EFI_ERROR(Status)) {
        goto ON_EXIT;
    }

    show("PkCert", PkCert, 32);

    Status = set_variable(EFI_PLATFORM_KEY_NAME, VariableGuid, Attr, DataSize,
                          PkCert);

    if (EFI_ERROR(Status)) {
        if (Status == EFI_OUT_OF_RESOURCES) {
        }
        goto ON_EXIT;
    }

ON_EXIT:

    if (PkCert != NULL) {
        free(PkCert);
    }

    return Status;
}
