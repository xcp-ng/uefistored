/**
 * auth.c - authenticated variables
 *
 * Inspired by and modified from edk2, with the license:
 *
 * Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
 * This program and the accompanying materials
 * are licensed and made available under the terms and conditions of the BSD License
 * which accompanies this distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php
 *
 * THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 */

#include <assert.h>

#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include "common.h"
#include "log.h"
#include "storage.h"
#include "uefi/auth_var_format.h"
#include "uefi/guids.h"
#include "uefi/global_variable.h"
#include "uefi/image_authentication.h"
#include "uefi/pkcs7_verify.h"
#include "uefi/types.h"
#include "uefi/utils.h"
#include "variable.h"

extern EFI_GUID gEfiGlobalVariableGuid;
extern EFI_GUID gEfiSecureBootEnableDisableGuid;

bool auth_enforce = true;
bool secure_boot_enabled;

extern bool efi_at_runtime;

extern SHA256_CTX *hash_ctx;
extern uint8_t setup_mode;

/* Public Exponent of RSA Key. */
const uint8_t sha256_oid[] = { 0x60, 0x86, 0x48, 0x01, 0x65,
                               0x03, 0x04, 0x02, 0x01 };

/*
 * Requirement for different signature type which have been defined in UEFI spec.
 * These data are used to perform SignatureList format check while setting PK/KEK variable.
 */
EFI_SIGNATURE_ITEM supported_sigs[] = {
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

/**
 * Construct a X509 object from DER-encoded certificate data.
 *
 * If cert is NULL, then return false.
 * If single_x509_cert is NULL, then return false.
 *
 * @parm cert Pointer to the DER-encoded certificate data.
 * @parm cert_size The size of certificate data in bytes.
 * @parm single_x509_cert The generated X509 object.
 *
 * @return true The X509 object generation succeeded.
 * @return false The operation failed.
 *
 */
bool x509_construct_certificate(const uint8_t *cert, uint64_t cert_size,
                                uint8_t **single_x509_cert)
{
    X509 *x509_cert;
    const uint8_t *temp;

    if (cert == NULL || single_x509_cert == NULL || cert_size > INT_MAX) {
        return false;
    }

    /*
     * Read DER-encoded X509 Certificate and Construct X509 object.
     */
    temp = cert;
    x509_cert = d2i_X509(NULL, &temp, (long)cert_size);
    if (x509_cert == NULL) {
        return false;
    }

    *single_x509_cert = (uint8_t *)x509_cert;

    return true;
}

/**
 * Retrieve the RSA Public Key from one DER-encoded X509 certificate.
 *
 * @parm cert         Pointer to the DER-encoded X509 certificate.
 * @parm cert_size    Size of the X509 certificate in bytes.
 * @parm rsa_context   Pointer to new-generated RSA context which contain the retrieved
 *                    RSA public key component. Use RsaFree() function to free the
 *                    resource.
 *
 * If cert is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @return true   RSA Public Key was retrieved successfully.
 * @return false  Fail to retrieve RSA public key from X509 certificate.
 *
 */
bool rsa_get_pub_key_from_x509(const uint8_t *cert, uint64_t cert_size,
                               void **rsa_context)
{
    bool status;
    EVP_PKEY *pkey = NULL;
    X509 *x509_cert = NULL;

    if (cert == NULL || rsa_context == NULL) {
        return false;
    }

    /*
     * Read DER-encoded X509 Certificate and Construct X509 object.
     */
    status = x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!status)) {
        status = false;
        goto err;
    }

    status = false;

    /*
     * Retrieve and check EVP_PKEY data from X509 Certificate.
     */
    pkey = X509_get_pubkey(x509_cert);
    if ((pkey == NULL) || (EVP_PKEY_id(pkey) != EVP_PKEY_RSA)) {
        goto err;
    }

    /*
     * Duplicate RSA Context from the retrieved EVP_PKEY.
     */
    //
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (((*rsa_context = RSAPublicKey_dup(rsa)) != NULL)) {
        status = true;
    }

    RSA_free(rsa);

err:
    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return status;
}

bool cert_equals_esl(uint8_t *cert_der, uint32_t cert_size,
                     EFI_SIGNATURE_LIST *old_esl)
{
    EFI_SIGNATURE_DATA *old_sig_data =
            (EFI_SIGNATURE_DATA *)((uint8_t *)old_esl +
                                   sizeof(EFI_SIGNATURE_LIST) +
                                   old_esl->SignatureHeaderSize);

    if (cert_size !=
        (old_esl->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1))) {
        return false;
    }

    if (memcmp(old_sig_data->SignatureData, cert_der, cert_size) != 0) {
        return false;
    }

    return true;
}

static EFI_STATUS X509_get_tbs_cert(X509 *cert, uint8_t **tbs_cert,
                                    UINTN *tbs_len)
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

/*
 * Calculate SHA256 digest of:
 *   SignerCert CommonName + ToplevelCert tbsCertificate
 * Adapted from edk2/varstored.
 */
static EFI_STATUS sha256_priv_sig(STACK_OF(X509) * certs, X509 *top_level_cert,
                                  uint8_t *digest)
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

    name_len = X509_NAME_get_text_by_NID(x509_name, NID_commonName, name,
                                         sizeof(name));
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
    EFI_SIGNATURE_LIST *certList;
    EFI_SIGNATURE_DATA *cert;
    uint64_t cert_count;
    EFI_SIGNATURE_LIST *new_cert_list;
    EFI_SIGNATURE_DATA *new_cert;
    uint64_t new_certCount;
    uint64_t i;
    uint64_t j;
    uint64_t Size;
    uint8_t *Tail;
    uint64_t CopiedCount;
    uint64_t SignatureListSize;
    bool is_new_cert;
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

    new_cert_list = (EFI_SIGNATURE_LIST *)new_data;
    while ((*new_data_size > 0) &&
           (*new_data_size >= new_cert_list->SignatureListSize)) {
        new_cert = (EFI_SIGNATURE_DATA *)((uint8_t *)new_cert_list +
                                          sizeof(EFI_SIGNATURE_LIST) +
                                          new_cert_list->SignatureHeaderSize);
        new_certCount =
                (new_cert_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                 new_cert_list->SignatureHeaderSize) /
                new_cert_list->SignatureSize;

        CopiedCount = 0;
        for (i = 0; i < new_certCount; i++) {
            is_new_cert = true;

            Size = data_size;
            certList = (EFI_SIGNATURE_LIST *)data;
            while ((Size > 0) && (Size >= certList->SignatureListSize)) {
                if (compare_guid(&certList->SignatureType,
                                 &new_cert_list->SignatureType) &&
                    (certList->SignatureSize == new_cert_list->SignatureSize)) {
                    cert = (EFI_SIGNATURE_DATA *)((uint8_t *)certList +
                                                  sizeof(EFI_SIGNATURE_LIST) +
                                                  certList->SignatureHeaderSize);
                    cert_count = (certList->SignatureListSize -
                                  sizeof(EFI_SIGNATURE_LIST) -
                                  certList->SignatureHeaderSize) /
                                 certList->SignatureSize;
                    for (j = 0; j < cert_count; j++) {
                        //
                        // Iterate each Signature data in this Signature List.
                        //
                        if (memcmp(new_cert, cert, certList->SignatureSize) ==
                            0) {
                            is_new_cert = false;
                            break;
                        }
                        cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert +
                                                      certList->SignatureSize);
                    }
                }

                if (!is_new_cert) {
                    break;
                }
                Size -= certList->SignatureListSize;
                certList = (EFI_SIGNATURE_LIST *)((uint8_t *)certList +
                                                  certList->SignatureListSize);
            }

            if (is_new_cert) {
                //
                // New EFI_SIGNATURE_DATA, keep it.
                //
                if (CopiedCount == 0) {
                    //
                    // Copy EFI_SIGNATURE_LIST header for only once.
                    //
                    memcpy(Tail, new_cert_list,
                           sizeof(EFI_SIGNATURE_LIST) +
                                   new_cert_list->SignatureHeaderSize);
                    Tail = Tail + sizeof(EFI_SIGNATURE_LIST) +
                           new_cert_list->SignatureHeaderSize;
                }

                memcpy(Tail, new_cert, new_cert_list->SignatureSize);
                Tail += new_cert_list->SignatureSize;
                CopiedCount++;
            }

            new_cert = (EFI_SIGNATURE_DATA *)((uint8_t *)new_cert +
                                              new_cert_list->SignatureSize);
        }

        //
        // Update SignatureListSize in the kept EFI_SIGNATURE_LIST.
        //
        if (CopiedCount != 0) {
            SignatureListSize = sizeof(EFI_SIGNATURE_LIST) +
                                new_cert_list->SignatureHeaderSize +
                                (CopiedCount * new_cert_list->SignatureSize);
            certList = (EFI_SIGNATURE_LIST *)(Tail - SignatureListSize);
            certList->SignatureListSize = (uint32_t)SignatureListSize;
        }

        *new_data_size -= new_cert_list->SignatureListSize;
        new_cert_list =
                (EFI_SIGNATURE_LIST *)((uint8_t *)new_cert_list +
                                       new_cert_list->SignatureListSize);
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
EFI_STATUS auth_internal_find_variable(UTF16 *name, size_t namesz,
                                       EFI_GUID *guid, void **data,
                                       uint64_t *data_size)
{
    variable_t *var;
    EFI_STATUS status;

    status = storage_get_var_ptr(&var, name, namesz, guid);

    if (status == EFI_SUCCESS) {
        *data_size = var->datasz;
        *data = var->data;
    }

    return status;
}

#define is_var(var, str)                                                       \
    (((var)->namesz == sizeof_wchar(str)) &&                                   \
     (memcmp((var)->name, str, (var)->namesz) == 0))

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
        UTF16 *name, size_t namesz, EFI_GUID *guid, void *data,
        uint64_t data_size, uint32_t attrs, EFI_TIME *timestamp)
{
    variable_t *var;
    EFI_STATUS find_status;

    find_status = storage_get_var_ptr(&var, name, namesz, guid);

    /*
     * EFI_VARIABLE_APPEND_WRITE attribute only effects for existing variable
     */
    if ((find_status == EFI_SUCCESS) &&
        ((var->attrs & EFI_VARIABLE_APPEND_WRITE) != 0)) {
        if (((compare_guid(&var->guid, &gEfiImageSecurityDatabaseGuid) &&
              (is_var(var, EFI_IMAGE_SECURITY_DATABASE) ||
               is_var(var, EFI_IMAGE_SECURITY_DATABASE1) ||
               is_var(var, EFI_IMAGE_SECURITY_DATABASE2))) ||
             (compare_guid(&var->guid, &gEfiGlobalVariableGuid) &&
              is_var(var, EFI_KEY_EXCHANGE_KEY_NAME)))) {
            /*
             * For variables with formatted as EFI_SIGNATURE_LIST, the driver
             * shall not perform an append of EFI_SIGNATURE_DATA values that are
             * already part of the existing variable value.
             */
            FilterSignatureList(var->data, var->datasz, data, &data_size);
        }
    }

    return storage_set_with_timestamp(name, namesz, guid, data, data_size,
                                      attrs, timestamp);
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

  @parm      mode                    SETUP_MODE or USER_MODE.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SUCCESS                     Update platform mode successfully.

**/
EFI_STATUS update_platform_mode(uint32_t mode)
{
    EFI_STATUS status;
    uint8_t deployed_mode;
    uint8_t secure_boot;

    assert(mode == USER_MODE || mode == SETUP_MODE);

    setup_mode = (uint8_t)mode;

    storage_set(L"SetupMode", sizeof_wchar(L"SetupMode"),
                &gEfiGlobalVariableGuid, &setup_mode, sizeof(setup_mode),
                EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);

    secure_boot = secure_boot_enabled;

    status = storage_set(
            EFI_SECURE_BOOT_MODE_NAME, sizeof_wchar(EFI_SECURE_BOOT_MODE_NAME),
            &gEfiGlobalVariableGuid, &secure_boot, sizeof(uint8_t),
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);

    if (mode == SETUP_MODE)
        deployed_mode = 1;
    else
        deployed_mode = 0;

    status = storage_set(
            L"DeployedMode", sizeof_wchar(L"DeployedMode"),
            &gEfiGlobalVariableGuid, &deployed_mode, sizeof(deployed_mode),
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);

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
EFI_STATUS check_signature_list_format(UTF16 *name, EFI_GUID *guid, void *data,
                                       uint64_t data_size)
{
    EFI_SIGNATURE_LIST *SigList;
    uint64_t sig_data_size;
    uint32_t i;
    uint32_t SigCount;
    bool is_pk;
    RSA *RsaContext;
    EFI_SIGNATURE_DATA *cert_data;
    uint64_t certLen;

    if (data_size == 0) {
        return EFI_SUCCESS;
    }

    assert(name != NULL && guid != NULL && data != NULL);

    if (compare_guid(guid, &gEfiGlobalVariableGuid) &&
        (strcmp16(name, EFI_PLATFORM_KEY_NAME) == 0)) {
        is_pk = true;
    } else if ((compare_guid(guid, &gEfiGlobalVariableGuid) &&
                (strcmp16(name, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) ||
               (compare_guid(guid, &gEfiImageSecurityDatabaseGuid) &&
                ((strcmp16(name, EFI_IMAGE_SECURITY_DATABASE) == 0) ||
                 (strcmp16(name, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
                 (strcmp16(name, EFI_IMAGE_SECURITY_DATABASE2) == 0)))) {
        is_pk = false;
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
    while ((sig_data_size > 0) &&
           (sig_data_size >= SigList->SignatureListSize)) {
        for (i = 0; i < (sizeof(supported_sigs) / sizeof(EFI_SIGNATURE_ITEM));
             i++) {
            if (compare_guid(&SigList->SignatureType,
                             &supported_sigs[i].SigType)) {
                //
                // The value of SignatureSize should always be 16 (size of SignatureOwner
                // component) add the data length according to signature type.
                //
                if (supported_sigs[i].SigDataSize != ((uint32_t)~0) &&
                    (SigList->SignatureSize - sizeof(EFI_GUID)) !=
                            supported_sigs[i].SigDataSize) {
                    return EFI_INVALID_PARAMETER;
                }
                if (supported_sigs[i].SigHeaderSize != ((uint32_t)~0) &&
                    SigList->SignatureHeaderSize !=
                            supported_sigs[i].SigHeaderSize) {
                    return EFI_INVALID_PARAMETER;
                }
                break;
            }
        }

        if (i == (sizeof(supported_sigs) / sizeof(EFI_SIGNATURE_ITEM))) {
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
            cert_data = (EFI_SIGNATURE_DATA *)((uint8_t *)SigList +
                                               sizeof(EFI_SIGNATURE_LIST) +
                                               SigList->SignatureHeaderSize);
            certLen = SigList->SignatureSize - sizeof(EFI_GUID);
            if (!rsa_get_pub_key_from_x509(cert_data->SignatureData, certLen,
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

    if (is_pk && SigCount > 1) {
        return EFI_INVALID_PARAMETER;
    }

    return EFI_SUCCESS;
}

/**
 * Compare two EFI_TIME data.
 *
 * @parm first A pointer to the first EFI_TIME data.
 * @parm second A pointer to the second EFI_TIME data.
 *
 * @return true The first is not later than the second.
 * @return false The first is later than the second.
 */
static bool auth_internal_compare_timestamp(EFI_TIME *first, EFI_TIME *second)
{
    if (first->Year != second->Year) {
        return (bool)(first->Year < second->Year);
    } else if (first->Month != second->Month) {
        return (bool)(first->Month < second->Month);
    } else if (first->Day != second->Day) {
        return (bool)(first->Day < second->Day);
    } else if (first->Hour != second->Hour) {
        return (bool)(first->Hour < second->Hour);
    } else if (first->Minute != second->Minute) {
        return (bool)(first->Minute < second->Minute);
    }

    return (bool)(first->Second <= second->Second);
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
  @parm cert_offset     Offset of matching cert_data, from starting of data.
  @parm cert_data_size   Length of cert_data in bytes.
  @parm cert_node_offset Offset of matching AUTH_CERT_DB_DATA , from
                             starting of data.
  @parm cert_node_size   Length of AUTH_CERT_DB_DATA in bytes.

  @return  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @return  EFI_NOT_FOUND         Fail to find matching certs.
  @return  EFI_SUCCESS           Find matching certs and output parameters.

**/
EFI_STATUS find_certs_from_db(UTF16 *name, EFI_GUID *guid, uint8_t *data,
                              uint64_t data_size, uint32_t *cert_offset,
                              uint32_t *cert_data_size,
                              uint32_t *cert_node_offset,
                              uint32_t *cert_node_size)
{
    uint32_t offset;
    AUTH_CERT_DB_DATA *ptr;
    uint32_t cert_size;
    uint32_t name_size;
    uint32_t node_size;
    uint32_t cert_db_list_size;

    if ((name == NULL) || (guid == NULL) || (data == NULL)) {
        return EFI_INVALID_PARAMETER;
    }

    //
    // Check whether data_size matches recorded cert_db_list_size.
    //
    if (data_size < sizeof(uint32_t)) {
        return EFI_INVALID_PARAMETER;
    }

    cert_db_list_size = ReadUnaligned32((uint32_t *)data);

    if (cert_db_list_size != (uint32_t)data_size) {
        return EFI_INVALID_PARAMETER;
    }

    offset = sizeof(uint32_t);

    //
    // Get corresponding certificates by guid and name.
    //
    while (offset < (uint32_t)data_size) {
        ptr = (AUTH_CERT_DB_DATA *)(data + offset);
        //
        // Check whether guid matches.
        //
        if (compare_guid(&ptr->VendorGuid, guid)) {
            node_size = ReadUnaligned32(&ptr->CertNodeSize);
            name_size = ReadUnaligned32(&ptr->NameSize);
            cert_size = ReadUnaligned32(&ptr->CertDataSize);

            if (node_size != sizeof(EFI_GUID) + sizeof(uint32_t) * 3 +
                                     cert_size + sizeof(UTF16) * name_size) {
                return EFI_INVALID_PARAMETER;
            }

            offset = offset + sizeof(EFI_GUID) + sizeof(uint32_t) * 3;
            //
            // Check whether name matches.
            //
            if ((name_size == strlen16(name)) &&
                (memcmp(data + offset, name, name_size * sizeof(UTF16)) == 0)) {
                offset = offset + name_size * sizeof(UTF16);

                if (cert_offset != NULL) {
                    *cert_offset = offset;
                }

                if (cert_data_size != NULL) {
                    *cert_data_size = cert_size;
                }

                if (cert_node_offset != NULL) {
                    *cert_node_offset = (uint32_t)((uint8_t *)ptr - data);
                }

                if (cert_node_size != NULL) {
                    *cert_node_size = node_size;
                }

                return EFI_SUCCESS;
            } else {
                offset = offset + name_size * sizeof(UTF16) + cert_size;
            }
        } else {
            node_size = ReadUnaligned32(&ptr->CertNodeSize);
            offset = offset + node_size;
        }
    }

    return EFI_NOT_FOUND;
}

X509 *X509_from_sig_data(EFI_SIGNATURE_DATA *sig, uint64_t sig_size)
{
    return X509_from_buf(sig->SignatureData,
                         sig_size - (sizeof(EFI_SIGNATURE_DATA) - 1));
}

/**
 * Verify that the PKCS7 SignedData signature is from the
 * X509 certificate in the payload.
 *
 * @return true if payload is signed by previous X509 priv key, otherwise false.
 */
static bool verify_payload(EFI_VARIABLE_AUTHENTICATION_2 *efi_auth,
                           uint8_t *payload_ptr, uint8_t *new_data,
                           uint64_t new_data_size)
{
    X509 *trusted_cert;
    EFI_SIGNATURE_LIST *cert_list;
    EFI_SIGNATURE_DATA *cert;
    PKCS7 *pkcs7;

    if (!efi_auth || !payload_ptr) {
        ERROR("verify_payload() passed null ptr\n");
        return false;
    }

    cert_list = (EFI_SIGNATURE_LIST *)payload_ptr;
    cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert_list +
                                  sizeof(EFI_SIGNATURE_LIST) +
                                  cert_list->SignatureHeaderSize);

    trusted_cert = X509_from_buf(cert->SignatureData,
                                 cert_list->SignatureSize -
                                         (sizeof(EFI_SIGNATURE_DATA) - 1));

    if (!trusted_cert) {
        DDEBUG("No trusted cert found\n");
        return false;
    }

    pkcs7 = pkcs7_from_auth(efi_auth);

    if (!pkcs7) {
        DDEBUG("Failed to parse pkcs7 from auth2\n");
        return false;
    }

    return pkcs7_verify(pkcs7, trusted_cert, new_data, new_data_size);
}

static EFI_STATUS sha256_from_auth(EFI_VARIABLE_AUTHENTICATION_2 *efi_auth,
                                   uint8_t digest[SHA256_DIGEST_SIZE])
{
    STACK_OF(X509) *signer_certs;
    X509 *top_cert;
    PKCS7 *pkcs7;
    EFI_STATUS status = EFI_SUCCESS;

    pkcs7 = pkcs7_from_auth(efi_auth);
    if (!pkcs7) {
        DDEBUG("Failed to parse pkcs7 from auth2\n");
        return EFI_SECURITY_VIOLATION;
    }

    status = pkcs7_get_signers(pkcs7, &signer_certs);
    if (status != EFI_SUCCESS) {
        WARNING("Failed to get pkcs7 signers\n");
        status = EFI_SECURITY_VIOLATION;
        goto free_pkcs7;
    }

    if (sk_X509_num(signer_certs) == 0) {
        WARNING("No pkcs7 signers found\n");
        status = EFI_SECURITY_VIOLATION;
        goto free_certs;
    }

    top_cert = sk_X509_value(signer_certs, sk_X509_num(signer_certs) - 1);

    if (!top_cert) {
        WARNING("No top cert found\n");
        status = EFI_SECURITY_VIOLATION;
        goto free_certs;
    }

    status = sha256_priv_sig(signer_certs, top_cert, digest);

    if (status != EFI_SUCCESS) {
        ERROR("Failed to create SHA256 digest of CN + tbsCertificate\n");
        status = EFI_SECURITY_VIOLATION;
    }

free_certs:
    sk_X509_free(signer_certs);
free_pkcs7:
    PKCS7_free(pkcs7);

    return status;
}

static bool verify_priv(EFI_VARIABLE_AUTHENTICATION_2 *efi_auth,
                        UTF16 *name, size_t namesz, EFI_GUID *guid,
                        uint8_t *sig_data, uint32_t sig_data_size,
                        uint8_t *new_data, uint64_t new_data_size)

{
    STACK_OF(X509) *signer_certs;
    X509 *top_cert;
    uint8_t digest[SHA256_DIGEST_SIZE];
    bool verify_status;
    EFI_STATUS status;
    PKCS7 *pkcs7;
    variable_t *var;

    pkcs7 = pkcs7_from_auth(efi_auth);
    if (!pkcs7) {
        DDEBUG("Failed to parse pkcs7 from auth2\n");
        return false;
    }

    status = pkcs7_get_signers(pkcs7, &signer_certs);
    if (status != EFI_SUCCESS) {
        WARNING("Failed to get pkcs7 signers\n");
        verify_status = false;
        goto free_pkcs7;
    }

    if (sk_X509_num(signer_certs) == 0) {
        WARNING("No pkcs7 signers found\n");
        verify_status = false;
        goto free_certs;
    }

    top_cert = sk_X509_value(signer_certs, sk_X509_num(signer_certs) - 1);

    if (!top_cert) {
        WARNING("No top cert found\n");
        verify_status = false;
        goto free_certs;
    }

    status = sha256_priv_sig(signer_certs, top_cert, digest);

    if (status != EFI_SUCCESS) {
        WARNING("Failed to create SHA256 digest of CN + tbsCertificate\n");
        verify_status = false;
        goto free_certs;
    }

    status = storage_get_var_ptr(&var, name, namesz, guid);

    if (status == EFI_SUCCESS) {
        /*
         * For private authenticated variables, permissive mode means that the
         * certificate used to sign the data does not need to match the
         * previous one. However, it still needs to exist and sign the data
         * correctly since it is used for verifying subsequent updates.
         */
        if (auth_enforce && memcmp(digest, var->cert, SHA256_DIGEST_SIZE)) {
            WARNING("SHA256 of CN + tbsCertificate not equal old variable\n");
            verify_status = false;
            goto free_certs;
        }
    }

    verify_status = Pkcs7Verify(sig_data, sig_data_size, top_cert, new_data,
                                new_data_size);
    if (!verify_status) {
        WARNING("Pkc7Verify failed\n");
        goto free_certs;
    }

free_certs:
    sk_X509_free(signer_certs);
free_pkcs7:
    PKCS7_free(pkcs7);
    return verify_status;
}

static bool verify_pk(EFI_VARIABLE_AUTHENTICATION_2 *efi_auth,
                      uint8_t *new_data, uint64_t new_data_size)
{
    bool ret;
    uint8_t *top_cert_der;
    int top_cert_der_size;
    PKCS7 *pkcs7;
    EFI_SIGNATURE_LIST *old_esl;
    uint64_t old_esl_size;
    EFI_STATUS status;

    pkcs7 = pkcs7_from_auth(efi_auth);

    if (!pkcs7) {
        DDEBUG("Failed to parse pkcs7 from auth2\n");
        return false;
    }

    top_cert_der = pkcs7_get_top_cert_der(pkcs7, &top_cert_der_size);

    if (!top_cert_der) {
        DDEBUG("No top cert found\n");
        return false;
    }

    status = auth_internal_find_variable(L"PK", sizeof_wchar(L"PK"),
                                         &gEfiGlobalVariableGuid,
                                         (void *)&old_esl, &old_esl_size);

    if (status != EFI_SUCCESS) {
        DDEBUG("No PK found\n");
        return false;
    }

    /*
     * The new PK must be signed with old PK, no chaining allowed so just use
     * the top and only cert.
     */
    if (!cert_equals_esl(top_cert_der, top_cert_der_size, old_esl)) {
        DDEBUG("PKCS7 SignedData cert not equal old PK!\n");
        return false;
    }

    /*
     * Verify Pkcs7 SignedData.
     */
    ret = pkcs7_verify(pkcs7, pkcs7_get_top_cert(pkcs7), new_data,
                       new_data_size);

    PKCS7_free(pkcs7);
    return ret;
}

static bool verify_kek(EFI_VARIABLE_AUTHENTICATION_2 *efi_auth,
                       uint8_t *new_data, uint64_t new_data_size)
{
    EFI_SIGNATURE_LIST *cert_list;
    EFI_SIGNATURE_DATA *cert;
    EFI_STATUS status;
    PKCS7 *pkcs7;
    X509 *trusted_cert;
    uint64_t i;
    void *kek;
    uint64_t kek_size;
    uint64_t cert_count;
    bool verify_status;

    /*
     * Get KEK database from variable.
     */
    status = auth_internal_find_variable(
            EFI_KEY_EXCHANGE_KEY_NAME, sizeof_wchar(EFI_KEY_EXCHANGE_KEY_NAME),
            &gEfiGlobalVariableGuid, &kek, &kek_size);

    if (status != EFI_SUCCESS) {
        DDEBUG("No KEK found!\n");
        return false;
    }

    pkcs7 = pkcs7_from_auth(efi_auth);

    if (!pkcs7) {
        DDEBUG("Failed to parse pkcs7 from auth2\n");
        return false;
    }

    cert_list = (EFI_SIGNATURE_LIST *)kek;
    while ((kek_size > 0) && (kek_size >= cert_list->SignatureListSize)) {
        if (compare_guid(&cert_list->SignatureType, &gEfiCertX509Guid)) {
            cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert_list +
                                          sizeof(EFI_SIGNATURE_LIST) +
                                          cert_list->SignatureHeaderSize);

            cert_count =
                    (cert_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
                     cert_list->SignatureHeaderSize) /
                    cert_list->SignatureSize;

            for (i = 0; i < cert_count; i++) {
                /*
                 * Iterate each Signature data Node within this cert_list for a verify
                 */
                trusted_cert =
                        X509_from_sig_data(cert, cert_list->SignatureSize);

                if (!trusted_cert) {
                    DDEBUG("no trusted cert found\n");
                    continue;
                }

                /*
                 * Verify Pkcs7 SignedData
                 */
                verify_status = pkcs7_verify(pkcs7, trusted_cert, new_data,
                                             new_data_size);

                if (verify_status) {
                    DDEBUG("pkcs7_verify() failed\n");
                    goto err;
                }

                cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert +
                                              cert_list->SignatureSize);
            }
        }

        kek_size -= cert_list->SignatureListSize;
        cert_list = (EFI_SIGNATURE_LIST *)((uint8_t *)cert_list +
                                           cert_list->SignatureListSize);
    }

err:
    PKCS7_free(pkcs7);
    return verify_status;
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
  @parm  auth_var_type                 Verify against PK, KEK database, private database or certificate in data payload.
  @parm  org_time_stamp                Pointer to original time stamp,
                                          original variable is not found if NULL.
  @parm  var_payload_ptr              Pointer to variable payload address.
  @parm  var_payload_size             Pointer to variable payload size.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
verify_time_based_payload(UTF16 *name, size_t namesz, EFI_GUID *guid,
                          void *data, uint64_t data_size, uint32_t attrs,
                          auth_var_t auth_var_type, EFI_TIME *org_time_stamp,
                          uint8_t **var_payload_ptr, uint64_t *var_payload_size)
{
    EFI_VARIABLE_AUTHENTICATION_2 *efi_auth = NULL;
    uint8_t *sig_data;
    uint32_t sig_data_size;
    uint8_t *payload_ptr;
    uint64_t payload_size;
    bool verify_status = false;
    EFI_STATUS status;
    uint8_t *new_data = NULL;
    uint64_t new_data_size;
    uint8_t *p;
    uint64_t length;
    uint8_t *wrap_data;
    uint32_t wrap_data_size;

    /*
     * 1. top_cert is the top-level issuer certificate in signature Signer Cert Chain
     * 2. trusted_cert is the certificate which firmware trusts. It could be saved in protected
     *     storage or PK payload on PK init
     *
     * When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is
     * set, then the data buffer shall begin with an instance of a complete (and serialized)
     * EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be followed by the new
     * variable value and data_size shall reflect the combined size of the descriptor and the new
     * variable value. The authentication descriptor is not part of the variable data and is not
     * returned by subsequent calls to GetVariable().
     */
    efi_auth = (EFI_VARIABLE_AUTHENTICATION_2 *)data;

    /*
     * Verify that Pad1, Nanosecond, TimeZone, Daylight and Pad2 components of the
     * TimeStamp value are set to zero.
     */
    if ((efi_auth->TimeStamp.Pad1 != 0) ||
        (efi_auth->TimeStamp.Nanosecond != 0) ||
        (efi_auth->TimeStamp.TimeZone != 0) ||
        (efi_auth->TimeStamp.Daylight != 0) ||
        (efi_auth->TimeStamp.Pad2 != 0)) {
        WARNING("Invalid TimeStamp in auth variable\n");
        return EFI_SECURITY_VIOLATION;
    }

    if ((org_time_stamp != NULL) &&
        ((attrs & EFI_VARIABLE_APPEND_WRITE) == 0)) {
        if (auth_internal_compare_timestamp(&efi_auth->TimeStamp,
                                            org_time_stamp)) {
            WARNING("TimeStamp check fail, suspicious replay attack: EFI_SECURITY_VIOLATION.");
            return EFI_SECURITY_VIOLATION;
        }
    }

    /*
     * wCertificateType should be WIN_CERT_TYPE_EFI_GUID.
     * Cert type should be EFI_CERT_TYPE_PKCS7_GUID.
     */
    if ((efi_auth->AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID) ||
        !compare_guid(&efi_auth->AuthInfo.CertType, &gEfiCertPkcs7Guid)) {
        WARNING("Invalid AuthInfo type, return EFI_SECURITY_VIOLATION.\n");
        return EFI_SECURITY_VIOLATION;
    }

    /*
     * Find out Pkcs7 SignedData which follows the EFI_VARIABLE_AUTHENTICATION_2 descriptor.
     * AuthInfo.Hdr.dwLength is the length of the entire certificate, including the length of the header.
     */
    sig_data = efi_auth->AuthInfo.CertData;
    sig_data_size = efi_auth->AuthInfo.Hdr.dwLength -
                    (uint32_t)(OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData));

    wrap_data =
            wrap_with_content_info(sig_data, sig_data_size, &wrap_data_size);

    if (!wrap_data) {
        ERROR("failed to wrap with ContentInfo\n");
        return EFI_DEVICE_ERROR;
    }

    //
    // SignedData.digestAlgorithms shall contain the digest algorithm used when preparing the
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
        if (wrap_data_size >= (32 + sizeof(sha256_oid))) {
            if (((*(wrap_data + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) ||
                (memcmp(wrap_data + 32, &sha256_oid, sizeof(sha256_oid)) !=
                 0)) {
                WARNING("VARIABLE_AUTHENTICATION_2 not using SHA256 (wrong oid)\n");
                return EFI_SECURITY_VIOLATION;
            }
        }
    }

    //
    // Find out the new data payload which follows Pkcs7 SignedData directly.
    //
    payload_ptr = sig_data + sig_data_size;
    payload_size =
            data_size - OFFSET_OF_AUTHINFO2_CERT_DATA - (uint64_t)sig_data_size;

    /*
     * Construct a serialization buffer of the values of the name, guid and attrs
     * parameters of the SetVariable() call and the TimeStamp component of the
     * EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable's new value
     * i.e. (name, guid, attrs, TimeStamp, data).
     */
    new_data_size = payload_size + sizeof(EFI_TIME) + sizeof(uint32_t) +
                    sizeof(EFI_GUID) + strsize16(name) - sizeof(UTF16);
    new_data = malloc(new_data_size);

    if (!new_data) {
        return EFI_OUT_OF_RESOURCES;
    }

    p = new_data;
    length = strlen16(name) * sizeof(UTF16);
    memcpy(p, name, length);
    p += length;

    length = sizeof(EFI_GUID);
    memcpy(p, guid, length);
    p += length;

    length = sizeof(uint32_t);
    memcpy(p, &attrs, length);
    p += length;

    length = sizeof(EFI_TIME);
    memcpy(p, &efi_auth->TimeStamp, length);
    p += length;

    memcpy(p, payload_ptr, payload_size);

    if (auth_var_type == AUTH_VAR_TYPE_PK) {
        verify_status = verify_pk(efi_auth, new_data, new_data_size);
    } else if (auth_var_type == AUTH_VAR_TYPE_PAYLOAD) {
        verify_status =
                verify_payload(efi_auth, payload_ptr, new_data, new_data_size);
    } else if (auth_var_type == AUTH_VAR_TYPE_KEK) {
        verify_status = verify_kek(efi_auth, new_data, new_data_size);
    } else if (auth_var_type == AUTH_VAR_TYPE_PRIV) {
        verify_status = verify_priv(efi_auth, name, namesz, guid, sig_data,
                                    sig_data_size, new_data, new_data_size);
    } else {
        DDEBUG("Invalid auth type: %u\n", auth_var_type);
        verify_status = false;
    }

    free(new_data);

    if (!verify_status) {
        return EFI_SECURITY_VIOLATION;
    }

    status = check_signature_list_format(name, guid, payload_ptr, payload_size);
    if (status != EFI_SUCCESS) {
        return status;
    }

    *var_payload_ptr = payload_ptr;
    *var_payload_size = payload_size;

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
  @parm  auth_var_type                 Verify against PK, KEK database, private database or certificate in data payload.
  @parm  var_del                      Delete the variable or not.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
verify_time_based_payload_and_update(UTF16 *name, size_t namesz, EFI_GUID *guid,
                                     void *data, uint64_t data_size,
                                     uint32_t attrs, auth_var_t auth_var_type,
                                     bool *var_del)
{
    EFI_STATUS status;
    EFI_STATUS find_status;
    uint8_t *payload_ptr;
    uint64_t payload_size;
    EFI_VARIABLE_AUTHENTICATION_2 *cert_data;
    bool is_del;
    EFI_TIME *time_stamp = NULL;
    variable_t *var = NULL;

    memset(&var, 0, sizeof(var));

    find_status = storage_get_var_ptr(&var, name, namesz, guid);

    if (find_status == EFI_SUCCESS) {
        time_stamp = &var->timestamp;
    }

    status = verify_time_based_payload(name, namesz, guid, data, data_size,
                                       attrs, auth_var_type, time_stamp,
                                       &payload_ptr, &payload_size);

    if (EFI_ERROR(status)) {
        DDEBUG("error=%s (0x%02lx)\n", efi_status_str(status), status);
        return status;
    }

    if (!EFI_ERROR(find_status) && (payload_size == 0) &&
        ((attrs & EFI_VARIABLE_APPEND_WRITE) == 0)) {
        is_del = true;
    } else {
        is_del = false;
    }

    cert_data = (EFI_VARIABLE_AUTHENTICATION_2 *)data;

    //
    // Final step: Update/Append Variable if it pass PKCS#7 verification
    //
    status = auth_internal_update_variable_with_timestamp(
            name, namesz, guid, payload_ptr, payload_size, attrs,
            &cert_data->TimeStamp);

    if (var_del != NULL) {
        if (is_del && (status == EFI_SUCCESS)) {
            *var_del = true;
        } else {
            *var_del = false;
        }
    }

    if (status == EFI_SUCCESS && !is_del) {
        status = storage_get_var_ptr(&var, name, namesz, guid);

        if (status != EFI_SUCCESS) {
            return status;
        }

        status = sha256_from_auth(cert_data, var->cert);

        if (status != EFI_SUCCESS) {
            return status;
        }
    }

    return status;
}

/**
  Process variable with platform key for verification.

  @parm name      Name of Variable to be found.
  @parm guid      Variable vendor GUID.
  @parm data      The data pointer.
  @parm data_size Size of data found. If size is less than the data,
                   this value contains the required size.
  @parm attrs     Attribute value of the variable
  @parm is_pk      Indicate whether it is to process pk.

  @return EFI_INVALID_PARAMETER   Invalid parameter.
  @return EFI_SECURITY_VIOLATION  The variable does NOT pass the validation.
                                  check carried out by the firmware.
  @return EFI_SUCCESS             Variable passed validation successfully.

**/
EFI_STATUS process_var_with_pk(UTF16 *name, size_t namesz, EFI_GUID *guid,
                               void *data, uint64_t data_size, uint32_t attrs,
                               bool is_pk)
{
    EFI_STATUS status;
    bool del;
    uint8_t *payload;
    uint64_t payload_size;

    if ((attrs & EFI_VARIABLE_NON_VOLATILE) == 0 ||
        (attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
        /*
         * PK, KEK and db/dbx/dbt should set EFI_VARIABLE_NON_VOLATILE
         * attribute and should be a time-based authenticated variable.
         */
        DDEBUG("Wrong attrs\n");
        return EFI_INVALID_PARAMETER;
    }

    /*
     * Init state of Del. State may change due to secure check
     */
    del = false;

    if (setup_mode == SETUP_MODE) {
        if (is_pk) {
            status = verify_time_based_payload_and_update(
                    name, namesz, guid, data, data_size, attrs,
                    AUTH_VAR_TYPE_PAYLOAD, &del);
        } else {
            payload = (uint8_t *)data + AUTHINFO2_SIZE(data);
            payload_size = data_size - AUTHINFO2_SIZE(data);

            if (payload_size == 0) {
                del = true;
            }

            status = check_signature_list_format(name, guid, payload,
                                                 payload_size);

            if (status) {
                DDEBUG("check_signature_list_format() = 0x%02lx\n", status);
                return status;
            }

            status = auth_internal_update_variable_with_timestamp(
                    name, namesz, guid, payload, payload_size, attrs,
                    &((EFI_VARIABLE_AUTHENTICATION_2 *)data)->TimeStamp);

            if (status) {
                DDEBUG("auth_internal_update_variable_with_timestamp() = 0x%02lx\n", status);
                return status;
            }
        }
    } else {
        /*
         * Verify against X509 Cert in PK database.
         */
        status = verify_time_based_payload_and_update(name, namesz, guid, data,
                                                      data_size, attrs,
                                                      AUTH_VAR_TYPE_PK, &del);
    }

    if (status == EFI_SUCCESS && is_pk) {
        if (setup_mode == SETUP_MODE && !del) {
            /*
             * If enroll PK in setup mode, need change to user mode.
             */
            status = update_platform_mode(USER_MODE);
        } else if (setup_mode == USER_MODE && del) {
            /*
             * If delete PK in user mode, need change to setup mode.
             */
            status = update_platform_mode(SETUP_MODE);
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

  @parm  name                    Name of Variable to be found.
  @parm  guid                    Variable vendor GUID.
  @parm  data                    data pointer.
  @parm  data_size               Size of data found. If size is less than the
                                 data, this value contains the required size.
  @parm  attrs                   Attribute value of the variable.

  @return EFI_INVALID_PARAMETER  Invalid parameter.
  @return EFI_SECURITY_VIOLATION The variable does NOT pass the validation
                                 check carried out by the firmware.
  @return EFI_SUCCESS            Variable pass validation successfully.

**/
EFI_STATUS process_var_with_kek(UTF16 *name, size_t namesz, EFI_GUID *guid,
                                void *data, uint64_t data_size, uint32_t attrs)
{
    EFI_STATUS status;
    uint8_t *payload;
    uint64_t payload_size;

    if ((attrs & EFI_VARIABLE_NON_VOLATILE) == 0 ||
        (attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
        /*
         * DB, DBX and DBT should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
         * authenticated variable.
         */
        return EFI_INVALID_PARAMETER;
    }

    status = EFI_SUCCESS;

    if (setup_mode == USER_MODE) {
        /*
         * Time-based, verify against X509 Cert KEK.
         */
        return verify_time_based_payload_and_update(name, namesz, guid, data,
                                                    data_size, attrs,
                                                    AUTH_VAR_TYPE_KEK, NULL);
    } else {
        /*
         * If in setup mode, no authentication needed.
         */
        payload = (uint8_t *)data + AUTHINFO2_SIZE(data);
        payload_size = data_size - AUTHINFO2_SIZE(data);

        status = check_signature_list_format(name, guid, payload, payload_size);
        if (status != EFI_SUCCESS) {
            return status;
        }

        status = auth_internal_update_variable_with_timestamp(
                name, namesz, guid, payload, payload_size, attrs,
                &((EFI_VARIABLE_AUTHENTICATION_2 *)data)->TimeStamp);
        if (status != EFI_SUCCESS) {
            return status;
        }
    }

    return status;
}

/**
  Check if it is to delete auth variable.

  @parm org_attrs      Original attribute value of the variable.
  @parm data               data pointer.
  @parm data_size           Size of data.
  @parm attrs         Attribute value of the variable.

  @return true                  It is to delete auth variable.
  @return false                 It is not to delete auth variable.

**/
bool is_delete_auth_variable(uint32_t org_attrs, void *data, uint64_t data_size,
                             uint32_t attrs)
{
    bool del;
    uint64_t payload_size;

    del = false;

    //
    // To delete a variable created with the EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
    // or the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute,
    // SetVariable must be used with attributes matching the existing variable
    // and the data_size set to the size of the AuthInfo descriptor.
    //
    if ((attrs == org_attrs) &&
        ((attrs & (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
                   EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) != 0)) {
        if ((attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
            payload_size = data_size - AUTHINFO2_SIZE(data);
            if (payload_size == 0) {
                del = true;
            }
        } else {
            payload_size = data_size - AUTHINFO_SIZE;
            if (payload_size == 0) {
                del = true;
            }
        }
    }

    return del;
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
EFI_STATUS process_variable(UTF16 *name, size_t namesz, EFI_GUID *guid,
                            void *data, uint64_t data_size, uint32_t attrs)
{
    variable_t *var;
    EFI_STATUS status;
    AUTH_VARIABLE_INFO org_variable_info;

    status = EFI_SUCCESS;

    memset(&org_variable_info, 0, sizeof(org_variable_info));

    /* Find the variable in our db */
    status = storage_get_var_ptr(&var, name, namesz, guid);

    /* If it was found and the caller is request its deletion, then delete it */
    if (status == EFI_SUCCESS &&
        is_delete_auth_variable(var->attrs, data, data_size, attrs)) {
        /*
         * Allow the delete operation of common authenticated variable(AT or AW)
         * at user physical presence.
         */
        return storage_set(name, namesz, guid, NULL, 0, 0);
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
        return verify_time_based_payload_and_update(name, namesz, guid, data,
                                                    data_size, attrs,
                                                    AUTH_VAR_TYPE_PRIV, NULL);
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
    return storage_set(name, namesz, guid, data, data_size, attrs);
}
