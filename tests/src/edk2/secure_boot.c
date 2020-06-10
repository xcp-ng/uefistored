#include "uefitypes.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern const EFI_GUID gEfiCertPkcs7Guid;
extern const EFI_GUID gEfiCertX509Guid;
extern const EFI_GUID gEfiGlobalVariableGuid;

#define OFFSET_OF(TYPE, Field) ((uint64_t) &(((TYPE *)0)->Field))
EFI_STATUS GetTime (EFI_TIME *Time)
{
}

typedef unsigned short CHAR16;

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
CreateTimeBasedPayload (
  uint64_t      *DataSize,
  uint8_t      **Data
  )
{
  EFI_STATUS                        Status;
  uint8_t                             *NewData;
  uint8_t                             *Payload;
  uint64_t                             PayloadSize;
  EFI_VARIABLE_AUTHENTICATION_2     *DescriptorData;
  uint64_t                             DescriptorSize;
  EFI_TIME                          Time;

  if (Data == NULL || DataSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // At user physical presence, the variable does not need to be signed but the
  // parameters to the SetVariable() call still need to be prepared as authenticated
  // variable. So we create EFI_VARIABLE_AUTHENTICATED_2 descriptor without certificate
  // data in it.
  //
  Payload     = *Data;
  PayloadSize = *DataSize;

  DescriptorSize = OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) + OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  NewData = (uint8_t *) malloc (DescriptorSize + PayloadSize);
  if (NewData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if ((Payload != NULL) && (PayloadSize != 0)) {
    memcpy (NewData + DescriptorSize, Payload, PayloadSize);
  }

  DescriptorData = (EFI_VARIABLE_AUTHENTICATION_2 *) (NewData);

  memset (&Time, 0, sizeof (EFI_TIME));
  Status = GetTime (&Time);
  if (EFI_ERROR (Status)) {
    free (NewData);
    return Status;
  }
  Time.Pad1       = 0;
  Time.Nanosecond = 0;
  Time.TimeZone   = 0;
  Time.Daylight   = 0;
  Time.Pad2       = 0;
  memcpy (&DescriptorData->TimeStamp, &Time, sizeof (EFI_TIME));

  DescriptorData->AuthInfo.Hdr.dwLength         = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  DescriptorData->AuthInfo.Hdr.wRevision        = 0x0200;
  DescriptorData->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  memcpy (&DescriptorData->AuthInfo.CertType, &gEfiCertPkcs7Guid, sizeof(EFI_GUID));

  if (Payload != NULL) {
    free (Payload);
  }

  *DataSize = DescriptorSize + PayloadSize;
  *Data     = NewData;
  return EFI_SUCCESS;
}

EFI_STATUS ReadFileContent(const char *file, void **data, uint64_t *datasize, int flag)
{
}

/**
  Generate the PK signature list from the X509 Certificate storing file (.cer)

  @param[in]   X509File              FileHandle of X509 Certificate storing file.
  @param[out]  PkCert                Point to the data buffer to store the signature list.

  @return EFI_UNSUPPORTED            Unsupported Key Length.
  @return EFI_OUT_OF_RESOURCES       There are not enough memory resourses to form the signature list.

**/
EFI_STATUS
CreatePkX509SignatureList (
    const char                  *X509File,
    EFI_SIGNATURE_LIST          **PkCert
  )
{
  EFI_STATUS              Status;
  uint8_t                   *X509Data;
  uint64_t                   X509DataSize;
  EFI_SIGNATURE_DATA      *PkCertData;

  X509Data = NULL;
  PkCertData = NULL;
  X509DataSize = 0;

  Status = ReadFileContent (X509File, (void**) &X509Data, &X509DataSize, 0);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }
  assert (X509Data != NULL);

  //
  // Allocate space for PK certificate list and initialize it.
  // Create PK database entry with SignatureHeaderSize equals 0.
  //
  *PkCert = (EFI_SIGNATURE_LIST*) malloc (
              sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1
              + X509DataSize
              );
  if (*PkCert == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  (*PkCert)->SignatureListSize   = (uint32_t) (sizeof(EFI_SIGNATURE_LIST)
                                    + sizeof(EFI_SIGNATURE_DATA) - 1
                                    + X509DataSize);
  (*PkCert)->SignatureSize       = (uint32_t) (sizeof(EFI_SIGNATURE_DATA) - 1 + X509DataSize);
  (*PkCert)->SignatureHeaderSize = 0;
  memcpy (&(*PkCert)->SignatureType, &gEfiCertX509Guid, sizeof(EFI_GUID));
  PkCertData                     = (EFI_SIGNATURE_DATA*) ((uint64_t)(*PkCert)
                                                          + sizeof(EFI_SIGNATURE_LIST)
                                                          + (*PkCert)->SignatureHeaderSize);
  memcpy (&PkCertData->SignatureOwner, &gEfiGlobalVariableGuid, sizeof(EFI_GUID));
  //
  // Fill the PK database with PKpub data from X509 certificate file.
  //
  memcpy (&(PkCertData->SignatureData[0]), X509Data, X509DataSize);

ON_EXIT:

  if (X509Data != NULL) {
    free (X509Data);
  }

  if (EFI_ERROR(Status) && *PkCert != NULL) {
    free (*PkCert);
    *PkCert = NULL;
  }

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
EnrollPlatformKey (
   char*   FileName
  )
{
  EFI_STATUS                      Status;
  uint32_t                          Attr;
  uint64_t                           DataSize;
  EFI_SIGNATURE_LIST              *PkCert;
  uint16_t*                         FilePostFix;
  uint64_t                           NameLength;

  if ( FileName == NULL) {
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
  NameLength = strlen (FileName);
  if (NameLength <= 4) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Prase the selected PK file and generature PK certificate list.
  //
  Status = CreatePkX509SignatureList (
            FileName,
            &PkCert
            );
  if (Status) {
    goto ON_EXIT;
  }
  assert (PkCert != NULL);

  //
  // Set Platform Key variable.
  //
  Attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS
          | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  DataSize = PkCert->SignatureListSize;
  Status = CreateTimeBasedPayload (&DataSize, (uint8_t**) &PkCert);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

#if 0
  Status = gRT->SetVariable(
                  EFI_PLATFORM_KEY_NAME,
                  &gEfiGlobalVariableGuid,
                  Attr,
                  DataSize,
                  PkCert
                  );
#endif
  if (EFI_ERROR (Status)) {
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
