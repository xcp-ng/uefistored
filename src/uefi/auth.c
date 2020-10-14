/**
 * auth.c - authenticated variables
 *
 * Inspired by and modified from edk2.
 */

#include <assert.h>

#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include "log.h"
#include "storage.h"
#include "uefi/auth_var_format.h"
#include "uefi/guids.h"
#include "uefi/global_variable.h"
#include "uefi/image_authentication.h"
#include "uefi/pkcs7_verify.h"
#include "uefi/types.h"
#include "uefi/utils.h"
#include "uefi/x509.h"
#include "variable.h"

bool auth_enforce = true;
bool secure_boot_enable;

extern bool efi_at_runtime;

extern SHA256_CTX *hash_ctx;
extern uint8_t setup_mode;

//
// Public Exponent of RSA Key.
//
const uint8_t mRsaE[] = { 0x01, 0x00, 0x01 };

const uint8_t mSha256OidValue[] = { 0x60, 0x86, 0x48, 0x01, 0x65,
                                    0x03, 0x04, 0x02, 0x01 };

//
// Requirement for different signature type which have been defined in UEFI spec.
// These data are used to perform SignatureList format check while setting PK/KEK variable.
//
EFI_SIGNATURE_ITEM mSupportSigItem[] = {
    //{SigType,                       SigHeaderSize,   sig_data_size  }
    { EFI_CERT_SHA256_GUID, 0, 32 },
    { EFI_CERT_RSA2048_GUID, 0, 256 },
    { EFI_CERT_RSA2048_SHA256_GUID, 0, 256 },
    { EFI_CERT_SHA1_GUID, 0, 20 },
    { EFI_CERT_RSA2048_SHA1_GUID, 0, 256 },
    { EFI_CERT_X509_GUID, 0, ((uint32_t)~0) },
    { EFI_CERT_SHA224_GUID, 0, 28 },
    { EFI_CERT_SHA384_GUID, 0, 48 },
    { EFI_CERT_SHA512_GUID, 0, 64 },
    { EFI_CERT_X509_SHA256_GUID, 0, 48 },
    { EFI_CERT_X509_SHA384_GUID, 0, 64 },
    { EFI_CERT_X509_SHA512_GUID, 0, 80 }
};

#if 0
static X509 *
X509_from_buf(const uint8_t *buf, long len)
{
    const uint8_t *ptr = buf;

    return d2i_X509(NULL, &ptr, len);
}
#endif

static EFI_STATUS
X509_get_tbs_cert(X509 *cert, uint8_t **tbs_cert, UINTN *tbs_len)
{
    int asn1_tag, obj_class, len;
    long tmp_len;
    uint8_t *buf, *ptr, *tbs_ptr;

    buf = X509_to_buf(cert, &len);
    if (!buf)
        return EFI_DEVICE_ERROR;

    ptr = buf;
    tmp_len = 0;
    ASN1_get_object((const unsigned char **)&ptr, &tmp_len, &asn1_tag,
                    &obj_class, len);
    if (asn1_tag != V_ASN1_SEQUENCE) {
        free(buf);
        return EFI_SECURITY_VIOLATION;
    }

    tbs_ptr = ptr;
    ASN1_get_object((const unsigned char **)&ptr, &tmp_len, &asn1_tag,
                    &obj_class, tmp_len);
    if (asn1_tag != V_ASN1_SEQUENCE) {
        free(buf);
        return EFI_SECURITY_VIOLATION;
    }

    *tbs_len = tmp_len + (ptr - tbs_ptr);
    *tbs_cert = malloc(*tbs_len);
    if (!*tbs_cert) {
        free(buf);
        return EFI_DEVICE_ERROR;
    }
    memcpy(*tbs_cert, tbs_ptr, *tbs_len);
    free(buf);

    return EFI_SUCCESS;
}


/**
 * Compare two guids.
 *
 * @parm guid1 A guid to compare
 * @parm guid2 A guid to compare
 *
 * @return true if two guids are equal, otherwise false.
 */
bool static inline compare_guid(EFI_GUID *guid1, EFI_GUID *guid2)
{
    return memcmp(guid1, guid2, sizeof(EFI_GUID)) == 0;
}

/*
 * Calculate SHA256 digest of:
 *   SignerCert CommonName + ToplevelCert tbsCertificate
 * Adapted from edk2/varstored.
 */
static EFI_STATUS sha256_priv_sig(STACK_OF(X509) *certs, X509 *top_level_cert, uint8_t *digest)
{
    SHA256_CTX ctx;
    char name[128];
    X509_NAME *x509_name;
    uint8_t *tbs_cert;
    UINTN tbs_cert_len;
    EFI_STATUS status;
    int name_len;

    x509_name = X509_get_subject_name(sk_X509_value(certs, 0));
    if (!x509_name)
        return EFI_SECURITY_VIOLATION;

    name_len = X509_NAME_get_text_by_NID(x509_name, NID_commonName,
                                         name, sizeof(name));
    if (name_len < 0)
        return EFI_SECURITY_VIOLATION;
    name_len++; /* Include trailing NUL character */

    status = X509_get_tbs_cert(top_level_cert, &tbs_cert, &tbs_cert_len);
    if (status != EFI_SUCCESS)
        return status;

    status = EFI_DEVICE_ERROR;
    if (!SHA256_Init(&ctx))
        goto out;

    if (!SHA256_Update(&ctx, name, strlen(name)))
        goto out;

    if (!SHA256_Update(&ctx, tbs_cert, tbs_cert_len))
        goto out;

    if (!SHA256_Final(digest, &ctx))
        goto out;

    status = EFI_SUCCESS;
out:
    free(tbs_cert);
    return status;
}

/**
  Filter out the duplicated EFI_SIGNATURE_DATA from the new data by comparing to the original data.

  @parm data          Pointer to original EFI_SIGNATURE_LIST.
  @parm data_size      Size of data buffer.
  @parm new_data       Pointer to new EFI_SIGNATURE_LIST.
  @parm new_data_size   Size of new_data buffer.

**/
EFI_STATUS
FilterSignatureList(void *data, uint64_t data_size, void *new_data,
                    uint64_t *new_data_size)
{
    EFI_SIGNATURE_LIST *CertList;
    EFI_SIGNATURE_DATA *Cert;
    uint64_t CertCount;
    EFI_SIGNATURE_LIST *NewCertList;
    EFI_SIGNATURE_DATA *NewCert;
    uint64_t NewCertCount;
    uint64_t Index;
    uint64_t Index2;
    uint64_t Size;
    uint8_t *Tail;
    uint64_t CopiedCount;
    uint64_t SignatureListSize;
    bool IsNewCert;
    uint8_t *Tempdata;
    uint64_t Tempdata_size;

    if (*new_data_size == 0) {
        return EFI_SUCCESS;
    }

    Tempdata_size = *new_data_size;
    Tempdata = malloc(Tempdata_size);

    if (!Tempdata) {
        return EFI_OUT_OF_RESOURCES;
    }

    Tail = Tempdata;

    NewCertList = (EFI_SIGNATURE_LIST *)new_data;
    while ((*new_data_size > 0) &&
           (*new_data_size >= NewCertList->SignatureListSize)) {
        NewCert = (EFI_SIGNATURE_DATA *)((uint8_t *)NewCertList +
                                         sizeof(EFI_SIGNATURE_LIST) +
                                         NewCertList->SignatureHeaderSize);
        NewCertCount =
                (NewCertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                 NewCertList->SignatureHeaderSize) /
                NewCertList->SignatureSize;

        CopiedCount = 0;
        for (Index = 0; Index < NewCertCount; Index++) {
            IsNewCert = true;

            Size = data_size;
            CertList = (EFI_SIGNATURE_LIST *)data;
            while ((Size > 0) && (Size >= CertList->SignatureListSize)) {
                if (compare_guid(&CertList->SignatureType,
                                 &NewCertList->SignatureType) &&
                    (CertList->SignatureSize == NewCertList->SignatureSize)) {
                    Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)CertList +
                                                  sizeof(EFI_SIGNATURE_LIST) +
                                                  CertList->SignatureHeaderSize);
                    CertCount = (CertList->SignatureListSize -
                                 sizeof(EFI_SIGNATURE_LIST) -
                                 CertList->SignatureHeaderSize) /
                                CertList->SignatureSize;
                    for (Index2 = 0; Index2 < CertCount; Index2++) {
                        //
                        // Iterate each Signature data in this Signature List.
                        //
                        if (memcmp(NewCert, Cert, CertList->SignatureSize) ==
                            0) {
                            IsNewCert = false;
                            break;
                        }
                        Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)Cert +
                                                      CertList->SignatureSize);
                    }
                }

                if (!IsNewCert) {
                    break;
                }
                Size -= CertList->SignatureListSize;
                CertList = (EFI_SIGNATURE_LIST *)((uint8_t *)CertList +
                                                  CertList->SignatureListSize);
            }

            if (IsNewCert) {
                //
                // New EFI_SIGNATURE_DATA, keep it.
                //
                if (CopiedCount == 0) {
                    //
                    // Copy EFI_SIGNATURE_LIST header for only once.
                    //
                    memcpy(Tail, NewCertList,
                           sizeof(EFI_SIGNATURE_LIST) +
                                   NewCertList->SignatureHeaderSize);
                    Tail = Tail + sizeof(EFI_SIGNATURE_LIST) +
                           NewCertList->SignatureHeaderSize;
                }

                memcpy(Tail, NewCert, NewCertList->SignatureSize);
                Tail += NewCertList->SignatureSize;
                CopiedCount++;
            }

            NewCert = (EFI_SIGNATURE_DATA *)((uint8_t *)NewCert +
                                             NewCertList->SignatureSize);
        }

        //
        // Update SignatureListSize in the kept EFI_SIGNATURE_LIST.
        //
        if (CopiedCount != 0) {
            SignatureListSize = sizeof(EFI_SIGNATURE_LIST) +
                                NewCertList->SignatureHeaderSize +
                                (CopiedCount * NewCertList->SignatureSize);
            CertList = (EFI_SIGNATURE_LIST *)(Tail - SignatureListSize);
            CertList->SignatureListSize = (uint32_t)SignatureListSize;
        }

        *new_data_size -= NewCertList->SignatureListSize;
        NewCertList = (EFI_SIGNATURE_LIST *)((uint8_t *)NewCertList +
                                             NewCertList->SignatureListSize);
    }

    Tempdata_size = (Tail - (uint8_t *)Tempdata);

    memcpy(new_data, Tempdata, Tempdata_size);
    *new_data_size = Tempdata_size;

    free(Tempdata);

    return EFI_SUCCESS;
}

/**
  Finds variable in storage blocks of volatile and non-volatile storage areas.

  This code finds variable in storage blocks of volatile and non-volatile storage areas.
  If name is an empty string, then we just return the first
  qualified variable without comparing name and guid.

  @parm name          Name of the variable to be found.
  @parm guid            Variable vendor GUID to be found.
  @parm data                  Pointer to data address.
  @parm data_size              Pointer to data size.

  @return EFI_INVALID_PARAMETER     If name is not an empty string,
                                    while guid is NULL.
  @return EFI_SUCCESS               Variable successfully found.
  @return EFI_NOT_FOUND             Variable not found

**/
EFI_STATUS auth_internal_find_variable(UTF16 *name, EFI_GUID *guid, void **data,
                                       uint64_t *data_size)
{
    variable_t *var;
    EFI_STATUS status;

    status = storage_get_var_ptr(&var, name, guid);

    if (status == EFI_SUCCESS) {
        *data_size = var->datasz;
        *data = var->data;
    }

    return status;
}

/**
  Update the variable region with Variable information.

  @parm name           Name of variable.
  @parm guid             Guid of variable.
  @parm data                   data pointer.
  @parm data_size               Size of data.
  @parm attrs             Attribute value of the variable.
  @parm timestamp              Value of associated timestamp.

  @return EFI_SUCCESS               The update operation is success.
  @return EFI_INVALID_PARAMETER     Invalid parameter.
  @return EFI_WRITE_PROTECTED       Variable is write-protected.
  @return EFI_OUT_OF_RESOURCES      There is not enough resource.

**/
EFI_STATUS auth_internal_update_variable_with_timestamp(
        UTF16 *name, EFI_GUID *guid, void *data, uint64_t data_size,
        uint32_t attrs, EFI_TIME *timestamp)
{
    variable_t *var;
    EFI_STATUS FindStatus;

    FindStatus = storage_get_var_ptr(&var, name, guid);

    /*
     * EFI_VARIABLE_APPEND_WRITE attribute only effects for existing variable
     */
    if (!EFI_ERROR(FindStatus) && ((var->attrs & EFI_VARIABLE_APPEND_WRITE) != 0)) {
        if ((compare_guid(&var->guid, &gEfiImageSecurityDatabaseGuid) &&
             ((strcmp16(var->name, EFI_IMAGE_SECURITY_DATABASE) == 0) ||
              (strcmp16(var->name, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
              (strcmp16(var->name, EFI_IMAGE_SECURITY_DATABASE2) == 0))) ||
            (compare_guid(&var->guid, &gEfiGlobalVariableGuid) &&
             (strcmp16(var->name, EFI_KEY_EXCHANGE_KEY_NAME) == 0))) {

            /*
             * For variables with formatted as EFI_SIGNATURE_LIST, the driver
             * shall not perform an append of EFI_SIGNATURE_DATA values that are
             * already part of the existing variable value.
             */
            FilterSignatureList(var->data, var->datasz, data, &data_size);
        }
    }

    return storage_set_with_timestamp(name, guid, data, data_size, attrs, timestamp);
}

/**
  Determine whether this operation needs a physical present user.

  @parm      name            Name of the Variable.
  @parm      guid              GUID of the Variable.

  @return true      This variable is protected, only a physical present user could set this variable.
  @return false     This variable is not protected.

**/
bool NeedPhysicallyPresent(UTF16 *name, EFI_GUID *guid)
{
    if (compare_guid(guid, &gEfiSecureBootEnableDisableGuid) &&
         (strcmp16(name, EFI_SECURE_BOOT_ENABLE_NAME) == 0)) {
        return true;
    }

    return false;
}

/**
  Update platform mode.

  @parm      Mode                    SETUP_MODE or USER_MODE.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SUCCESS                     Update platform mode successfully.

**/
EFI_STATUS UpdatePlatformMode(uint32_t Mode)
{
    EFI_STATUS status;
    void *data;
    uint64_t data_size;
    uint8_t SecureBootMode;
    uint8_t SecureBootEnable;
    uint64_t Variabledata_size;

    status = auth_internal_find_variable(
            EFI_SETUP_MODE_NAME, &gEfiGlobalVariableGuid, &data, &data_size);
    if (EFI_ERROR(status)) {
        return status;
    }

    //
    // Update the value of SetupMode variable by a simple mem copy, this could avoid possible
    // variable storage reclaim at runtime.
    //
    setup_mode = (uint8_t)Mode;
    memcpy(data, &setup_mode, sizeof(uint8_t));

    if (efi_at_runtime) {
        //
        // SecureBoot Variable indicates whether the platform firmware is operating
        // in Secure boot mode (1) or not (0), so we should not change SecureBoot
        // Variable in runtime.
        //
        return status;
    }

    //
    // Check "SecureBoot" variable's existence.
    // If it doesn't exist, firmware has no capability to perform driver signing verification,
    // then set "SecureBoot" to 0.
    //
    status = auth_internal_find_variable(EFI_SECURE_BOOT_MODE_NAME,
                                         &gEfiGlobalVariableGuid, &data,
                                         &data_size);
    //
    // If "SecureBoot" variable exists, then check "setup_mode" variable update.
    // If "setup_mode" variable is USER_MODE, "SecureBoot" variable is set to 1.
    // If "setup_mode" variable is SETUP_MODE, "SecureBoot" variable is set to 0.
    //
    if (EFI_ERROR(status)) {
        SecureBootMode = SECURE_BOOT_MODE_DISABLE;
    } else {
        if (setup_mode == USER_MODE) {
            SecureBootMode = SECURE_BOOT_MODE_ENABLE;
        } else if (setup_mode == SETUP_MODE) {
            SecureBootMode = SECURE_BOOT_MODE_DISABLE;
        } else {
            return EFI_NOT_FOUND;
        }
    }

    status = storage_set(EFI_SECURE_BOOT_MODE_NAME, &gEfiGlobalVariableGuid,
                         &SecureBootMode, sizeof(uint8_t),
                         EFI_VARIABLE_RUNTIME_ACCESS |
                                 EFI_VARIABLE_BOOTSERVICE_ACCESS);
    if (EFI_ERROR(status)) {
        return status;
    }

    //
    // Check "SecureBootEnable" variable's existence. It can enable/disable secure boot feature.
    //
    status = auth_internal_find_variable(EFI_SECURE_BOOT_ENABLE_NAME,
                                         &gEfiSecureBootEnableDisableGuid,
                                         &data, &data_size);

    if (SecureBootMode == SECURE_BOOT_MODE_ENABLE) {
        //
        // Create the "SecureBootEnable" variable as secure boot is enabled.
        //
        SecureBootEnable = SECURE_BOOT_ENABLE;
        Variabledata_size = sizeof(SecureBootEnable);
    } else {
        //
        // Delete the "SecureBootEnable" variable if this variable exist as "SecureBoot"
        // variable is not in secure boot state.
        //
        if (EFI_ERROR(status)) {
            return EFI_SUCCESS;
        }
        SecureBootEnable = SECURE_BOOT_DISABLE;
        Variabledata_size = 0;
    }

    status = storage_set(
            EFI_SECURE_BOOT_ENABLE_NAME, &gEfiSecureBootEnableDisableGuid,
            &SecureBootEnable, Variabledata_size,
            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS);
    return status;
}

/**
  Check input data form to make sure it is a valid EFI_SIGNATURE_LIST for PK/KEK/db/dbx/dbt variable.

  @parm  name                Name of Variable to be check.
  @parm  guid                  Variable vendor GUID.
  @parm  data                        Point to the variable data to be checked.
  @parm  data_size                    Size of data.

  @return EFI_INVALID_PARAMETER           Invalid signature list format.
  @return EFI_SUCCESS                     Passed signature list format check successfully.

**/
EFI_STATUS CheckSignatureListFormat(UTF16 *name, EFI_GUID *guid, void *data,
                                    uint64_t data_size)
{
    EFI_SIGNATURE_LIST *SigList;
    uint64_t sig_data_size;
    uint32_t Index;
    uint32_t SigCount;
    bool IsPk;
    RSA *RsaContext;
    EFI_SIGNATURE_DATA *CertData;
    uint64_t CertLen;

    if (data_size == 0) {
        return EFI_SUCCESS;
    }

    assert(name != NULL && guid != NULL && data != NULL);

    if (compare_guid(guid, &gEfiGlobalVariableGuid) &&
        (strcmp16(name, EFI_PLATFORM_KEY_NAME) == 0)) {
        IsPk = true;
    } else if ((compare_guid(guid, &gEfiGlobalVariableGuid) &&
                (strcmp16(name, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) ||
               (compare_guid(guid, &gEfiImageSecurityDatabaseGuid) &&
                ((strcmp16(name, EFI_IMAGE_SECURITY_DATABASE) == 0) ||
                 (strcmp16(name, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
                 (strcmp16(name, EFI_IMAGE_SECURITY_DATABASE2) == 0)))) {
        IsPk = false;
    } else {
        return EFI_SUCCESS;
    }

    SigCount = 0;
    SigList = (EFI_SIGNATURE_LIST *)data;
    sig_data_size = data_size;
    RsaContext = NULL;

    //
    // Walk throuth the input signature list and check the data format.
    // If any signature is incorrectly formed, the whole check will fail.
    //
    while ((sig_data_size > 0) && (sig_data_size >= SigList->SignatureListSize)) {
        for (Index = 0;
             Index < (sizeof(mSupportSigItem) / sizeof(EFI_SIGNATURE_ITEM));
             Index++) {
            if (compare_guid(&SigList->SignatureType,
                             &mSupportSigItem[Index].SigType)) {
                //
                // The value of SignatureSize should always be 16 (size of SignatureOwner
                // component) add the data length according to signature type.
                //
                if (mSupportSigItem[Index].SigDataSize != ((uint32_t)~0) &&
                    (SigList->SignatureSize - sizeof(EFI_GUID)) !=
                            mSupportSigItem[Index].SigDataSize) {
                    return EFI_INVALID_PARAMETER;
                }
                if (mSupportSigItem[Index].SigHeaderSize != ((uint32_t)~0) &&
                    SigList->SignatureHeaderSize !=
                            mSupportSigItem[Index].SigHeaderSize) {
                    return EFI_INVALID_PARAMETER;
                }
                break;
            }
        }

        if (Index == (sizeof(mSupportSigItem) / sizeof(EFI_SIGNATURE_ITEM))) {
            //
            // Undefined signature type.
            //
            return EFI_INVALID_PARAMETER;
        }

        if (compare_guid(&SigList->SignatureType, &gEfiCertX509Guid)) {
            //
            // Try to retrieve the RSA public key from the X.509 certificate.
            // If this operation fails, it's not a valid certificate.
            //
            CertData = (EFI_SIGNATURE_DATA *)((uint8_t *)SigList +
                                              sizeof(EFI_SIGNATURE_LIST) +
                                              SigList->SignatureHeaderSize);
            CertLen = SigList->SignatureSize - sizeof(EFI_GUID);
            if (!RsaGetPublicKeyFromX509(CertData->SignatureData, CertLen,
                                         (void *)&RsaContext)) {
                return EFI_INVALID_PARAMETER;
            }
        }

        if ((SigList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
             SigList->SignatureHeaderSize) %
                    SigList->SignatureSize !=
            0) {
            return EFI_INVALID_PARAMETER;
        }
        SigCount += (SigList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                     SigList->SignatureHeaderSize) /
                    SigList->SignatureSize;

        sig_data_size -= SigList->SignatureListSize;
        SigList = (EFI_SIGNATURE_LIST *)((uint8_t *)SigList +
                                         SigList->SignatureListSize);
    }

    if (((uint64_t)SigList - (uint64_t)data) != data_size) {
        return EFI_INVALID_PARAMETER;
    }

    if (IsPk && SigCount > 1) {
        return EFI_INVALID_PARAMETER;
    }

    return EFI_SUCCESS;
}

/**
  Compare two EFI_TIME data.


  @parm FirstTime           A pointer to the first EFI_TIME data.
  @parm SecondTime          A pointer to the second EFI_TIME data.

  @return  true              The FirstTime is not later than the SecondTime.
  @return  false             The FirstTime is later than the SecondTime.

**/
bool auth_internal_compare_timestamp(EFI_TIME *FirstTime, EFI_TIME *SecondTime)
{
    if (FirstTime->Year != SecondTime->Year) {
        return (bool)(FirstTime->Year < SecondTime->Year);
    } else if (FirstTime->Month != SecondTime->Month) {
        return (bool)(FirstTime->Month < SecondTime->Month);
    } else if (FirstTime->Day != SecondTime->Day) {
        return (bool)(FirstTime->Day < SecondTime->Day);
    } else if (FirstTime->Hour != SecondTime->Hour) {
        return (bool)(FirstTime->Hour < SecondTime->Hour);
    } else if (FirstTime->Minute != SecondTime->Minute) {
        return (bool)(FirstTime->Minute < SecondTime->Minute);
    }

    return (bool)(FirstTime->Second <= SecondTime->Second);
}

/**
  Find matching signer's certificates for common authenticated variable
  by corresponding name and guid from "certdb" or "certdbv".

  The data format of "certdb" or "certdbv":
  //
  //     uint32_t CertDbListSize;
  // /// AUTH_CERT_DB_DATA Certs1[];
  // /// AUTH_CERT_DB_DATA Certs2[];
  // /// ...
  // /// AUTH_CERT_DB_DATA Certsn[];
  //

  @parm  name   Name of authenticated Variable.
  @parm  guid     Vendor GUID of authenticated Variable.
  @parm  data           Pointer to variable "certdb" or "certdbv".
  @parm  data_size       Size of variable "certdb" or "certdbv".
  @parm CertOffset     Offset of matching CertData, from starting of data.
  @parm CertDataSize   Length of CertData in bytes.
  @parm CertNodeOffset Offset of matching AUTH_CERT_DB_DATA , from
                             starting of data.
  @parm CertNodeSize   Length of AUTH_CERT_DB_DATA in bytes.

  @return  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @return  EFI_NOT_FOUND         Fail to find matching certs.
  @return  EFI_SUCCESS           Find matching certs and output parameters.

**/
EFI_STATUS FindCertsFromDb(UTF16 *name, EFI_GUID *guid, uint8_t *data,
                           uint64_t data_size, uint32_t *CertOffset,
                           uint32_t *CertDataSize, uint32_t *CertNodeOffset,
                           uint32_t *CertNodeSize)
{
    uint32_t Offset;
    AUTH_CERT_DB_DATA *Ptr;
    uint32_t CertSize;
    uint32_t NameSize;
    uint32_t NodeSize;
    uint32_t CertDbListSize;

    if ((name == NULL) || (guid == NULL) || (data == NULL)) {
        return EFI_INVALID_PARAMETER;
    }

    //
    // Check whether data_size matches recorded CertDbListSize.
    //
    if (data_size < sizeof(uint32_t)) {
        return EFI_INVALID_PARAMETER;
    }

    CertDbListSize = ReadUnaligned32((uint32_t *)data);

    if (CertDbListSize != (uint32_t)data_size) {
        return EFI_INVALID_PARAMETER;
    }

    Offset = sizeof(uint32_t);

    //
    // Get corresponding certificates by guid and name.
    //
    while (Offset < (uint32_t)data_size) {
        Ptr = (AUTH_CERT_DB_DATA *)(data + Offset);
        //
        // Check whether guid matches.
        //
        if (compare_guid(&Ptr->VendorGuid, guid)) {
            NodeSize = ReadUnaligned32(&Ptr->CertNodeSize);
            NameSize = ReadUnaligned32(&Ptr->NameSize);
            CertSize = ReadUnaligned32(&Ptr->CertDataSize);

            if (NodeSize != sizeof(EFI_GUID) + sizeof(uint32_t) * 3 + CertSize +
                                    sizeof(UTF16) * NameSize) {
                return EFI_INVALID_PARAMETER;
            }

            Offset = Offset + sizeof(EFI_GUID) + sizeof(uint32_t) * 3;
            //
            // Check whether name matches.
            //
            if ((NameSize == strlen16(name)) &&
                (memcmp(data + Offset, name, NameSize * sizeof(UTF16)) == 0)) {
                Offset = Offset + NameSize * sizeof(UTF16);

                if (CertOffset != NULL) {
                    *CertOffset = Offset;
                }

                if (CertDataSize != NULL) {
                    *CertDataSize = CertSize;
                }

                if (CertNodeOffset != NULL) {
                    *CertNodeOffset = (uint32_t)((uint8_t *)Ptr - data);
                }

                if (CertNodeSize != NULL) {
                    *CertNodeSize = NodeSize;
                }

                return EFI_SUCCESS;
            } else {
                Offset = Offset + NameSize * sizeof(UTF16) + CertSize;
            }
        } else {
            NodeSize = ReadUnaligned32(&Ptr->CertNodeSize);
            Offset = Offset + NodeSize;
        }
    }

    return EFI_NOT_FOUND;
}

/**
  Retrieve signer's certificates for common authenticated variable
  by corresponding name and guid from "certdb"
  or "certdbv" according to authenticated variable attributes.

  @parm  name   Name of authenticated Variable.
  @parm  guid     Vendor GUID of authenticated Variable.
  @parm  attrs        attrs of authenticated variable.
  @parm CertData       Pointer to signer's certificates.
  @parm CertDataSize   Length of CertData in bytes.

  @return  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @return  EFI_NOT_FOUND         Fail to find "certdb"/"certdbv" or matching certs.
  @return  EFI_SUCCESS           Get signer's certificates successfully.

**/
EFI_STATUS
GetCertsFromDb(UTF16 *name, EFI_GUID *guid, uint32_t attrs, uint8_t **CertData,
               uint32_t *CertDataSize)
{
    EFI_STATUS status;
    uint8_t *data;
    uint64_t data_size;
    uint32_t CertOffset;
    UTF16 *DbName;

    if ((name == NULL) || (guid == NULL) || (CertData == NULL) ||
        (CertDataSize == NULL)) {
        return EFI_INVALID_PARAMETER;
    }

    if ((attrs & EFI_VARIABLE_NON_VOLATILE) != 0) {
        //
        // Get variable "certdb".
        //
        DbName = EFI_CERT_DB_NAME;
    } else {
        //
        // Get variable "certdbv".
        //
        DbName = EFI_CERT_DB_VOLATILE_NAME;
    }

    //
    // Get variable "certdb" or "certdbv".
    //
    status = auth_internal_find_variable(DbName, &gEfiCertDbGuid,
                                         (void **)&data, &data_size);
    if (EFI_ERROR(status)) {
        free(data);
        return status;
    }

    if ((data_size == 0) || (data == NULL)) {
        free(data);
        return EFI_NOT_FOUND;
    }

    status = FindCertsFromDb(name, guid, data, data_size, &CertOffset,
                             CertDataSize, NULL, NULL);

    if (EFI_ERROR(status)) {
        free(data);
        return status;
    }

    *CertData = data + CertOffset;
    return EFI_SUCCESS;
}

/**
  Calculate SHA256 digest of SignerCert CommonName + ToplevelCert tbsCertificate
  SignerCert and ToplevelCert are inside the signer certificate chain.

  @parm  SignerCert          A pointer to SignerCert data.
  @parm  SignerCertSize      Length of SignerCert data.
  @parm  TopLevelCert        A pointer to TopLevelCert data.
  @parm  TopLevelCertSize    Length of TopLevelCert data.
  @parm Sha256Digest       Sha256 digest calculated.

  @return EFI_ABORTED          Digest process failed.
  @return EFI_SUCCESS          SHA256 Digest is succesfully calculated.

**/
EFI_STATUS
CalculatePrivAuthVarSignChainSHA256Digest(uint8_t *SignerCert,
                                          uint64_t SignerCertSize,
                                          uint8_t *TopLevelCert,
                                          uint64_t TopLevelCertSize,
                                          uint8_t *Sha256Digest)
{
    uint8_t *TbsCert;
    uint64_t TbsCertSize;
    CHAR8 CertCommonName[128];
    uint64_t CertCommonNameSize;
    bool Cryptostatus;
    EFI_STATUS status;

    CertCommonNameSize = sizeof(CertCommonName);

    //
    // Get SignerCert CommonName
    //
    status = X509GetCommonName(SignerCert, SignerCertSize, CertCommonName,
                               &CertCommonNameSize);
    if (EFI_ERROR(status)) {
        DDEBUG("Get SignerCert CommonName failed with status %lx\n", status);
        return EFI_ABORTED;
    }

    //
    // Get TopLevelCert tbsCertificate
    //
    if (!X509GetTBSCert(TopLevelCert, TopLevelCertSize, &TbsCert,
                        &TbsCertSize)) {
        DDEBUG("Get Top-level Cert tbsCertificate failed!\n");
        return EFI_ABORTED;
    }

    //
    // Digest SignerCert CN + TopLevelCert tbsCertificate
    //
    memset(Sha256Digest, 0, SHA256_DIGEST_SIZE);
    Cryptostatus = SHA256_Init(hash_ctx);
    if (!Cryptostatus) {
        return EFI_ABORTED;
    }

    //
    // '\0' is forced in CertCommonName. No overflow issue
    //
    Cryptostatus =
            SHA256_Update(hash_ctx, CertCommonName, strlen(CertCommonName));
    if (!Cryptostatus) {
        return EFI_ABORTED;
    }

    Cryptostatus = SHA256_Update(hash_ctx, TbsCert, TbsCertSize);
    if (!Cryptostatus) {
        return EFI_ABORTED;
    }

    Cryptostatus = SHA256_Final(Sha256Digest, hash_ctx);
    if (!Cryptostatus) {
        return EFI_ABORTED;
    }

    return EFI_SUCCESS;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @parm  name                Name of Variable to be found.
  @parm  guid                  Variable vendor GUID.
  @parm  data                        data pointer.
  @parm  data_size                    Size of data found. If size is less than the
                                          data, this value contains the required size.
  @parm  attrs                  Attribute value of the variable.
  @parm  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @parm  OrgTimeStamp                Pointer to original time stamp,
                                          original variable is not found if NULL.
  @parm  VarPayloadPtr              Pointer to variable payload address.
  @parm  VarPayloadSize             Pointer to variable payload size.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifyTimeBasedPayload(UTF16 *name, EFI_GUID *guid, void *data,
                       uint64_t data_size, uint32_t attrs,
                       AUTHVAR_TYPE AuthVarType, EFI_TIME *OrgTimeStamp,
                       uint8_t **VarPayloadPtr, uint64_t *VarPayloadSize)
{
    EFI_VARIABLE_AUTHENTICATION_2 *CertData = NULL;
    uint8_t *sig_data;
    uint32_t sig_data_size;
    uint8_t *PayloadPtr;
    uint64_t PayloadSize;
    uint32_t Attr = attrs;
    bool verify_status = false;
    EFI_STATUS status;
    EFI_SIGNATURE_LIST *CertList;
    EFI_SIGNATURE_DATA *Cert;
    uint64_t Index;
    uint64_t CertCount;
    uint32_t kek_data_size;
    uint8_t *new_data = NULL;
    uint64_t new_data_size;
    uint8_t *Buffer;
    uint64_t Length;
    X509 *TopLevelCert = NULL;
    uint8_t *TopLevelCertBuf;
    int TopLevelCertSize;
    X509 *TrustedCert;
    STACK_OF(X509) *SignerCerts = NULL;
    uint64_t CertStackSize;
    uint8_t digest[SHA256_DIGEST_SIZE];

    //
    // 1. TopLevelCert is the top-level issuer certificate in signature Signer Cert Chain
    // 2. TrustedCert is the certificate which firmware trusts. It could be saved in protected
    //     storage or PK payload on PK init
    //

    //
    // When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is
    // set, then the data buffer shall begin with an instance of a complete (and serialized)
    // EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be followed by the new
    // variable value and data_size shall reflect the combined size of the descriptor and the new
    // variable value. The authentication descriptor is not part of the variable data and is not
    // returned by subsequent calls to GetVariable().
    //
    CertData = (EFI_VARIABLE_AUTHENTICATION_2 *)data;

    //
    // Verify that Pad1, Nanosecond, TimeZone, Daylight and Pad2 components of the
    // TimeStamp value are set to zero.
    //
    if ((CertData->TimeStamp.Pad1 != 0) ||
        (CertData->TimeStamp.Nanosecond != 0) ||
        (CertData->TimeStamp.TimeZone != 0) ||
        (CertData->TimeStamp.Daylight != 0) ||
        (CertData->TimeStamp.Pad2 != 0)) {
        return EFI_SECURITY_VIOLATION;
    }

    if ((OrgTimeStamp != NULL) && ((attrs & EFI_VARIABLE_APPEND_WRITE) == 0)) {
        if (auth_internal_compare_timestamp(&CertData->TimeStamp,
                                            OrgTimeStamp)) {
            //
            // TimeStamp check fail, suspicious replay attack, return EFI_SECURITY_VIOLATION.
            //
            return EFI_SECURITY_VIOLATION;
        }
    }

    //
    // wCertificateType should be WIN_CERT_TYPE_EFI_GUID.
    // Cert type should be EFI_CERT_TYPE_PKCS7_GUID.
    //
    if ((CertData->AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID) ||
        !compare_guid(&CertData->AuthInfo.CertType, &gEfiCertPkcs7Guid)) {
        //
        // Invalid AuthInfo type, return EFI_SECURITY_VIOLATION.
        //
        return EFI_SECURITY_VIOLATION;
    }

    //
    // Find out Pkcs7 Signeddata which follows the EFI_VARIABLE_AUTHENTICATION_2 descriptor.
    // AuthInfo.Hdr.dwLength is the length of the entire certificate, including the length of the header.
    //
    sig_data = CertData->AuthInfo.CertData;
    sig_data_size = CertData->AuthInfo.Hdr.dwLength -
                  (uint32_t)(OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData));

    uint8_t *WrapData;
    uint64_t WrapDataSize;
    bool Wrapped;

    if (!WrapPkcs7Data(sig_data, sig_data_size, &Wrapped,
                       &WrapData, &WrapDataSize)) {
        return EFI_DEVICE_ERROR;
    }

    DDEBUG("sig_data_size=%u, WrapDataSize=%lu\n", sig_data_size, WrapDataSize);

    //
    // Signeddata.digestAlgorithms shall contain the digest algorithm used when preparing the
    // signature. Only a digest algorithm of SHA-256 is accepted.
    //
    //    According to PKCS#7 Definition:
    //        SignedData ::= SEQUENCE {
    //            version Version,
    //            digestAlgorithms DigestAlgorithmIdentifiers,
    //            contentInfo ContentInfo,
    //            .... }
    //    The DigestAlgorithmIdentifiers can be used to determine the hash algorithm
    //    in VARIABLE_AUTHENTICATION_2 descriptor.
    //    This field has the fixed offset (+13) and be calculated based on two bytes of length encoding.
    //
    if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
        if (WrapDataSize >= (32 + sizeof(mSha256OidValue))) {
            if (((*(WrapData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) ||
                (memcmp(WrapData + 32, &mSha256OidValue,
                        sizeof(mSha256OidValue)) != 0)) {
                return EFI_SECURITY_VIOLATION;
            }
        }
    }

    //
    // Find out the new data payload which follows Pkcs7 Signeddata directly.
    //
    PayloadPtr = sig_data + sig_data_size;
    PayloadSize =
            data_size - OFFSET_OF_AUTHINFO2_CERT_DATA - (uint64_t)sig_data_size;

    //
    // Construct a serialization buffer of the values of the name, guid and attrs
    // parameters of the SetVariable() call and the TimeStamp component of the
    // EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable's new value
    // i.e. (name, guid, attrs, TimeStamp, data)
    //
    new_data_size = PayloadSize + sizeof(EFI_TIME) + sizeof(uint32_t) +
                   sizeof(EFI_GUID) + strsize16(name) - sizeof(UTF16);

    //
    // Here is to reuse scratch data area(at the end of volatile variable store)
    // to reduce SMRAM consumption for SMM variable driver.
    // The scratch buffer is enough to hold the serialized data and safe to use,
    // because it is only used at here to do verification temporarily first
    // and then used in UpdateVariable() for a time based auth variable set.
    //
    new_data = malloc(new_data_size);

    if (!new_data) {
        return EFI_OUT_OF_RESOURCES;
    }

    Buffer = new_data;
    Length = strlen16(name) * sizeof(UTF16);
    memcpy(Buffer, name, Length);
    Buffer += Length;

    Length = sizeof(EFI_GUID);
    memcpy(Buffer, guid, Length);
    Buffer += Length;

    Length = sizeof(uint32_t);
    memcpy(Buffer, &Attr, Length);
    Buffer += Length;

    Length = sizeof(EFI_TIME);
    memcpy(Buffer, &CertData->TimeStamp, Length);
    Buffer += Length;

    memcpy(Buffer, PayloadPtr, PayloadSize);

    if (AuthVarType == AuthVarTypePk) {
        /*
         * Verify that the signature has been made with the current Platform
         * Key (no chaining for PK).  First, get signer's certificates from
         * signed_data.
         */
        verify_status = Pkcs7GetSigners(sig_data, sig_data_size,
                                        &SignerCerts, &CertStackSize);
        if (!verify_status) {
            goto done;
        }

        TopLevelCert = sk_X509_value(SignerCerts, sk_X509_num(SignerCerts) - 1);

        TopLevelCertBuf = X509_to_buf(TopLevelCert, &TopLevelCertSize);
        if (!TopLevelCertBuf) {
            status = EFI_DEVICE_ERROR;
            goto done;
        }

        /*
         * Second, get the current platform key from variable. Check whether
         * it's identical with signer's certificates in SignedData. If not,
         * return error immediately.
         */
        status = auth_internal_find_variable(EFI_PLATFORM_KEY_NAME,
                                             &gEfiGlobalVariableGuid, &data,
                                             &data_size);
        if (EFI_ERROR(status)) {
            verify_status = false;
            goto done;
        }

        CertList = (EFI_SIGNATURE_LIST *)data;
        Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)CertList +
                                      sizeof(EFI_SIGNATURE_LIST) +
                                      CertList->SignatureHeaderSize);

        if (TopLevelCertSize !=
             (CertList->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1))) {
            verify_status = false;
            goto done;
        }

        if (memcmp(Cert->SignatureData, TopLevelCertBuf, TopLevelCertSize) != 0) {
            verify_status = false;
            goto done;
        }

        /*
         * Verify Pkcs7 SignedData.
         */
        verify_status = Pkcs7Verify(sig_data, sig_data_size, TopLevelCert,
                                   new_data, new_data_size);

    } else if (AuthVarType == AuthVarTypeKek) {
        //
        // Get KEK database from variable.
        //
        status = auth_internal_find_variable(EFI_KEY_EXCHANGE_KEY_NAME,
                                             &gEfiGlobalVariableGuid, &data,
                                             &data_size);
        if (EFI_ERROR(status)) {
            free(new_data);
            return status;
        }

        //
        // Ready to verify Pkcs7 Signeddata. Go through KEK Signature database to find out X.509 CertList.
        //
        kek_data_size = (uint32_t)data_size;
        CertList = (EFI_SIGNATURE_LIST *)data;
        while ((kek_data_size > 0) &&
               (kek_data_size >= CertList->SignatureListSize)) {
            if (compare_guid(&CertList->SignatureType, &gEfiCertX509Guid)) {
                Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)CertList +
                                              sizeof(EFI_SIGNATURE_LIST) +
                                              CertList->SignatureHeaderSize);
                CertCount = (CertList->SignatureListSize -
                             sizeof(EFI_SIGNATURE_LIST) -
                             CertList->SignatureHeaderSize) /
                            CertList->SignatureSize;
                for (Index = 0; Index < CertCount; Index++) {

                    /*
                     * Iterate each Signature data Node within this CertList for a verify
                     */
                    TrustedCert = X509_from_buf(Cert->SignatureData,
                                                CertList->SignatureSize -
                                                (sizeof(EFI_SIGNATURE_DATA) - 1));

                    /*
                    TrustedCertSize = CertList->SignatureSize -
                                      (sizeof(EFI_SIGNATURE_DATA) - 1);
                                      */

                    //
                    // Verify Pkcs7 Signeddata via Pkcs7Verify library.
                    //
                    verify_status =
                            Pkcs7Verify(sig_data, sig_data_size, TrustedCert,
                                        new_data, new_data_size);
                    if (verify_status) {
                        goto done;
                    }
                    Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)Cert +
                                                  CertList->SignatureSize);
                }
            }
            kek_data_size -= CertList->SignatureListSize;
            CertList = (EFI_SIGNATURE_LIST *)((uint8_t *)CertList +
                                              CertList->SignatureListSize);
        }
    } else if (AuthVarType == AuthVarTypePriv) {
        (void)CertStackSize;
        (void)digest;

        PKCS7 *pkcs7;

        status = pkcs7_get_signers(WrapData, WrapDataSize, &pkcs7, &SignerCerts);

        if (status != EFI_SUCCESS) {
            verify_status = false;
            goto done;
        }

        if (sk_X509_num(SignerCerts) == 0) {
            verify_status = false;
            goto done;
        }

        TopLevelCert = sk_X509_value(SignerCerts, sk_X509_num(SignerCerts) - 1);

        status = sha256_priv_sig(SignerCerts, TopLevelCert, digest);
        if (status != EFI_SUCCESS) {
            goto done;
        }

        variable_t *var;

        status = storage_get_var_ptr(&var, name, guid);

        if (status == EFI_SUCCESS) {
            /*
             * For private authenticated variables, permissive mode means that the
             * certificate used to sign the data does not need to match the
             * previous one. However, it still needs to exist and sign the data
             * correctly since it is used for verifying subsequent updates.
             */
            if (auth_enforce && memcmp(digest, var->cert, SHA256_DIGEST_SIZE)) {
                verify_status = false;
                status = EFI_SECURITY_VIOLATION;
                goto done;
            }
        }

        verify_status = Pkcs7Verify(sig_data, sig_data_size, TopLevelCert,
                                    new_data, new_data_size);
        if (!verify_status) {
            goto done;
        }
    } else if (AuthVarType == AuthVarTypePayload) {
        CertList = (EFI_SIGNATURE_LIST *)PayloadPtr;
        Cert = (EFI_SIGNATURE_DATA *)((uint8_t *)CertList +
                                      sizeof(EFI_SIGNATURE_LIST) +
                                      CertList->SignatureHeaderSize);
        /*
         * TrustedCert = (X509*)Cert->SignatureData;
         * TrustedCertSize =
         *        CertList->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1);
        */
        TrustedCert = X509_from_buf(Cert->SignatureData,
                                    CertList->SignatureSize -
                                    (sizeof(EFI_SIGNATURE_DATA) - 1));

        //
        // Verify Pkcs7 Signeddata via Pkcs7Verify library.
        //
        verify_status = Pkcs7Verify(sig_data, sig_data_size, TrustedCert,
                                   new_data, new_data_size);
    } else {
        free(new_data);
        return EFI_SECURITY_VIOLATION;
    }

done:
    free(new_data);

    if (AuthVarType == AuthVarTypePk || AuthVarType == AuthVarTypePriv) {
        sk_X509_free(SignerCerts);
    }

    if (!verify_status) {
        return EFI_SECURITY_VIOLATION;
    }

    status = CheckSignatureListFormat(name, guid, PayloadPtr, PayloadSize);
    if (EFI_ERROR(status)) {
        return status;
    }

    *VarPayloadPtr = PayloadPtr;
    *VarPayloadSize = PayloadSize;

    return EFI_SUCCESS;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @parm  name                Name of Variable to be found.
  @parm  guid                  Variable vendor GUID.
  @parm  data                        data pointer.
  @parm  data_size                    Size of data found. If size is less than the
                                          data, this value contains the required size.
  @parm  attrs                  Attribute value of the variable.
  @parm  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @parm  VarDel                      Delete the variable or not.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
verify_time_based_payload_and_update(UTF16 *name, EFI_GUID *guid, void *data,
                                     uint64_t data_size, uint32_t attrs,
                                     AUTHVAR_TYPE AuthVarType, bool *VarDel)
{
    EFI_STATUS status;
    EFI_STATUS FindStatus;
    uint8_t *PayloadPtr;
    uint64_t PayloadSize;
    EFI_VARIABLE_AUTHENTICATION_2 *CertData;
    bool IsDel;
    EFI_TIME *TimeStamp = NULL;
    variable_t *var = NULL;

    memset(&var, 0, sizeof(var));

    FindStatus = storage_get_var_ptr(&var, name, guid);

    if (FindStatus == EFI_SUCCESS) {
        TimeStamp = &var->timestamp;
    }

    status = VerifyTimeBasedPayload(
            name, guid, data, data_size, attrs, AuthVarType,
            TimeStamp,
            &PayloadPtr, &PayloadSize);

    if (EFI_ERROR(status)) {
        DDEBUG("error=%s (0x%02lx)\n", efi_status_str(status), status); 
        return status;
    }

    if (!EFI_ERROR(FindStatus) && (PayloadSize == 0) &&
        ((attrs & EFI_VARIABLE_APPEND_WRITE) == 0)) {
        IsDel = true;
    } else {
        IsDel = false;
    }

    CertData = (EFI_VARIABLE_AUTHENTICATION_2 *)data;

    //
    // Final step: Update/Append Variable if it pass Pkcs7Verify
    //
    status = auth_internal_update_variable_with_timestamp(
            name, guid, PayloadPtr, PayloadSize, attrs, &CertData->TimeStamp);

    //
    // Delete signer's certificates when delete the common authenticated variable.
    //
    if (IsDel && AuthVarType == AuthVarTypePriv && !EFI_ERROR(status)) {

        //status = delete_certs_from_db(name, guid, attrs);
    }

    if (VarDel != NULL) {
        if (IsDel && !EFI_ERROR(status)) {
            *VarDel = true;
        } else {
            *VarDel = false;
        }
    }

    DDEBUG("status=%s (0x%02lx)\n", efi_status_str(status), status); 
    return status;
}

/**
  Process variable with platform key for verification.

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @parm name      Name of Variable to be found.
  @parm guid      Variable vendor GUID.
  @parm data      The data pointer.
  @parm data_size Size of data found. If size is less than the data,
                   this value contains the required size.
  @parm attrs     Attribute value of the variable
  @parm IsPk      Indicate whether it is to process pk.

  @return EFI_INVALID_PARAMETER   Invalid parameter.
  @return EFI_SECURITY_VIOLATION  The variable does NOT pass the validation.
                                  check carried out by the firmware.
  @return EFI_SUCCESS             Variable passed validation successfully.

**/
EFI_STATUS process_var_with_pk(UTF16 *name, EFI_GUID *guid, void *data,
                            uint64_t data_size, uint32_t attrs, bool IsPk)
{
    EFI_STATUS status;
    bool Del;
    uint8_t *Payload;
    uint64_t PayloadSize;

    if ((attrs & EFI_VARIABLE_NON_VOLATILE) == 0 ||
        (attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
        /*
         * PK, KEK and db/dbx/dbt should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
         * authenticated variable.
         */
        return EFI_INVALID_PARAMETER;
    }

    /*
     * Init state of Del. State may change due to secure check
     */
    Del = false;

    if (setup_mode == SETUP_MODE && !IsPk) {
        Payload = (uint8_t *)data + AUTHINFO2_SIZE(data);
        PayloadSize = data_size - AUTHINFO2_SIZE(data);

        if (PayloadSize == 0) {
            Del = true;
        }

        status = CheckSignatureListFormat(name, guid, Payload, PayloadSize);

        if (EFI_ERROR(status)) {
            return status;
        }

        status = auth_internal_update_variable_with_timestamp(
                name, guid, Payload, PayloadSize, attrs,
                &((EFI_VARIABLE_AUTHENTICATION_2 *)data)->TimeStamp);

        if (EFI_ERROR(status)) {
            return status;
        }
    } else if (setup_mode == USER_MODE) {
        /*
         * Verify against X509 Cert in PK database.
         */
        status = verify_time_based_payload_and_update(
                name, guid, data, data_size, attrs, AuthVarTypePk, &Del);
    } else {
        /*
         * Verify against the certificate in data payload.
         */
        status = verify_time_based_payload_and_update(
                name, guid, data, data_size, attrs, AuthVarTypePayload, &Del);
    }

    if (!EFI_ERROR(status) && IsPk) {
        if (setup_mode == SETUP_MODE && !Del) {
            //
            // If enroll PK in setup mode, need change to user mode.
            //
            status = UpdatePlatformMode(USER_MODE);
        } else if (setup_mode == USER_MODE && Del) {
            //
            // If delete PK in user mode, need change to setup mode.
            //
            status = UpdatePlatformMode(SETUP_MODE);
        }
    }

    return status;
}

/**
  Process variable with key exchange key for verification.

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @parm  name                Name of Variable to be found.
  @parm  guid                  Variable vendor GUID.
  @parm  data                        data pointer.
  @parm  data_size                    Size of data found. If size is less than the
                                          data, this value contains the required size.
  @parm  attrs                  Attribute value of the variable.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS ProcessVarWithKek(UTF16 *name, EFI_GUID *guid, void *data,
                             uint64_t data_size, uint32_t attrs)
{
    EFI_STATUS status;
    uint8_t *Payload;
    uint64_t PayloadSize;

    if ((attrs & EFI_VARIABLE_NON_VOLATILE) == 0 ||
        (attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
        //
        // DB, DBX and DBT should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
        // authenticated variable.
        //
        return EFI_INVALID_PARAMETER;
    }

    status = EFI_SUCCESS;

    if (setup_mode == USER_MODE) {
        //
        // Time-based, verify against X509 Cert KEK.
        //
        return verify_time_based_payload_and_update(
                name, guid, data, data_size, attrs, AuthVarTypeKek, NULL);
    } else {
        //
        // If in setup mode or custom secure boot mode, no authentication needed.
        //
        Payload = (uint8_t *)data + AUTHINFO2_SIZE(data);
        PayloadSize = data_size - AUTHINFO2_SIZE(data);

        status = CheckSignatureListFormat(name, guid, Payload, PayloadSize);
        if (EFI_ERROR(status)) {
            return status;
        }

        status = auth_internal_update_variable_with_timestamp(
                name, guid, Payload, PayloadSize, attrs,
                &((EFI_VARIABLE_AUTHENTICATION_2 *)data)->TimeStamp);
        if (EFI_ERROR(status)) {
            return status;
        }
    }

    return status;
}

/**
  Check if it is to delete auth variable.

  @parm Orgattrs      Original attribute value of the variable.
  @parm data               data pointer.
  @parm data_size           Size of data.
  @parm attrs         Attribute value of the variable.

  @return true                  It is to delete auth variable.
  @return false                 It is not to delete auth variable.

**/
bool is_delete_auth_variable(uint32_t Orgattrs, void *data, uint64_t data_size,
                             uint32_t attrs)
{
    bool Del;
    uint64_t PayloadSize;

    Del = false;

    //
    // To delete a variable created with the EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
    // or the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute,
    // SetVariable must be used with attributes matching the existing variable
    // and the data_size set to the size of the AuthInfo descriptor.
    //
    if ((attrs == Orgattrs) &&
        ((attrs & (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
                   EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) != 0)) {
        if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
            PayloadSize = data_size - AUTHINFO2_SIZE(data);
            if (PayloadSize == 0) {
                Del = true;
            }
        } else {
            PayloadSize = data_size - AUTHINFO_SIZE;
            if (PayloadSize == 0) {
                Del = true;
            }
        }
    }

    return Del;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  This function will do basic validation, before parsing the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @parm  name Name of the variable.
  @parm  guid Variable vendor GUID.
  @parm  data data pointer.
  @parm  data_size Size of data.
  @parm  attrs Attribute value of the variable.

  @return EFI_INVALID_PARAMETER Invalid parameter.
  @return EFI_WRITE_PROTECTED Variable is write-protected and needs authentication with
                              EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS or EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set.
  @return EFI_OUT_OF_RESOURCES The database to save the public key is full.
  @return EFI_SECURITY_VIOLATION The variable is with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                                 set, but the AuthInfo does NOT pass the validation
                                 check carried out by the firmware.
  @return EFI_SUCCESS Variable is not write-protected or pass validation successfully.

**/
EFI_STATUS process_variable(UTF16 *name, EFI_GUID *guid, void *data,
                            uint64_t data_size, uint32_t attrs)
{
    variable_t *var;
    EFI_STATUS status;
    AUTH_VARIABLE_INFO org_variable_info;

    status = EFI_SUCCESS;

    memset(&org_variable_info, 0, sizeof(org_variable_info));

    /* Find the variable in our db */
    status = storage_get_var_ptr(&var, name, guid);


    /* If it was found and the caller is request its deletion, then delete it */
    if (status == EFI_SUCCESS &&
        is_delete_auth_variable(var->attrs, data, data_size,
                                attrs)) {
        /*
         * Allow the delete operation of common authenticated variable(AT or AW)
         * at user physical presence.
         */
        status = storage_set(name, guid, NULL, 0, 0);

        if (status != EFI_SUCCESS) {
            return status;
        }

        if (((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) !=
             0)) {
            //status = delete_certs_from_db(name, guid, attrs);
        }

        DDEBUG("status=0x%02lx\n", status);
        return status;
    }

    if ((attrs & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != 0) {
        /*
         * Reject Counter Based Auth Variable processing request.
         */
        return EFI_UNSUPPORTED;
    } else if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) !=
               0) {
        /*
         * Process Time-based Authenticated variable.
         */
        return verify_time_based_payload_and_update(
                name, guid, data, data_size, attrs, AuthVarTypePriv, NULL);
    }

    if ((org_variable_info.Data != NULL) &&
        ((org_variable_info.Attributes &
          (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
           EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) != 0)) {
        /*
         * If the variable is already write-protected, it always needs authentication before update.
         */
        return EFI_WRITE_PROTECTED;
    }

    /*
     * Not authenticated variable, just update variable as usual.
     */
    return storage_set(name, guid, data, data_size, attrs);
}

/**
  Clean up signer's certificates for common authenticated variable
  by corresponding name and guid from "certdb".
  System may break down during Timebased Variable update & certdb update,
  make them inconsistent,  this function is called in AuthVariable Init
  to ensure consistency.

  @return  EFI_NOT_FOUND         Fail to find variable "certdb".
  @return  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @return  EFI_SUCCESS           The operation is completed successfully.

**/
EFI_STATUS
CleanCertsFromDb(void)
{
    uint32_t Offset;
    AUTH_CERT_DB_DATA *Ptr;
    uint32_t NameSize;
    uint32_t NodeSize;
    UTF16 *name;
    EFI_STATUS status;
    bool CertCleaned;
    uint8_t *data;
    uint64_t data_size;
    EFI_GUID AuthVarGuid;
    AUTH_VARIABLE_INFO AuthVariableInfo;

    status = EFI_SUCCESS;

    //
    // Get corresponding certificates by guid and name.
    //
    do {
        CertCleaned = false;

        //
        // Get latest variable "certdb"
        //
        status = auth_internal_find_variable(EFI_CERT_DB_NAME, &gEfiCertDbGuid,
                                             (void **)&data, &data_size);
        if (EFI_ERROR(status)) {
            return status;
        }

        if ((data_size == 0) || (data == NULL)) {
            return EFI_NOT_FOUND;
        }

        Offset = sizeof(uint32_t);

        while (Offset < (uint32_t)data_size) {
            Ptr = (AUTH_CERT_DB_DATA *)(data + Offset);
            NodeSize = ReadUnaligned32(&Ptr->CertNodeSize);
            NameSize = ReadUnaligned32(&Ptr->NameSize);

            //
            // Get VarName tailed with '\0'
            //
            name = malloc((NameSize + 1) * sizeof(UTF16));
            if (name == NULL) {
                return EFI_OUT_OF_RESOURCES;
            }
            memcpy(name, (uint8_t *)Ptr + sizeof(AUTH_CERT_DB_DATA),
                   NameSize * sizeof(UTF16));
            //
            // Keep VarGuid  aligned
            //
            memcpy(&AuthVarGuid, &Ptr->VendorGuid, sizeof(EFI_GUID));

            //
            // Find corresponding time auth variable
            //
            memset(&AuthVariableInfo, 0, sizeof(AuthVariableInfo));

            variable_t var;

            status = storage_get_var(&var, name, &AuthVarGuid);

            if (EFI_ERROR(status) ||
                (var.attrs &
                 EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
                //status = delete_certs_from_db(name, &AuthVarGuid, var.attrs);
                CertCleaned = true;

                DDEBUG("Recovery!! Cert for Auth Variable is removed for consistency\n");
                free(name);
                variable_destroy_noalloc(&var);
                break;
            }

            variable_destroy_noalloc(&var);
            free(name);
            Offset = Offset + NodeSize;
        }
    } while (CertCleaned);

    return status;
}
