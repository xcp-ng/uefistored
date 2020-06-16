#include <stdlib.h>
#include <stdint.h>
#include "uefitypes.h"
#include "varnames.h"
#include "uefi_guids.h"

const uint8_t SHA256_OID_VAL[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

/**
 * Returns true of time stamp a and b are equal, according to
 * the security checks necessary for authenticated vars.
 */
static bool auth_compare_time_stamp(EFI_TIME *a, EFI_TIME *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  caution: this function may receive untrusted input.
  this function may be invoked in smm mode, and datasize and data are external input.
  this function will do basic validation, before parse the data.
  this function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  name                name of variable to be found.
  @param[in]  vendor_guid                  variable vendor guid.
  @param[in]  data                        data pointer.
  @param[in]  data_size                    size of data found. if size is less than the
                                          data, this value contains the required size.
  @param[in]  attributes                  attribute value of the variable.
  @param[in]  auth_var_type                 verify against pk, kek database, private database or certificate in data payload.
  @param[in]  org_time_stamp                pointer to original time stamp,
                                          original variable is not found if NULL.
  @param[out]  var_payload_ptr              pointer to variable payload address.
  @param[out]  var_payload_size             pointer to variable payload size.

  @retval EFI_INVALID_PARAMETER           invalid parameter.
  @retval EFI_SECURITY_VIOLATION          the variable does not pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     variable pass validation successfully.

**/
EFI_STATUS verify_timebased_payload(UTF16 *name, EFI_GUID *vendor_guid,
                                    void *data, uint64_t data_size,
                                    uint32_t attributes, auth_var_t auth_var_type,
                                    EFI_TIME *org_time_stamp, uint8_t **var_payload_ptr,
                                    uint64_t *var_payload_size
  )
{
    EFI_VARIABLE_AUTHENTICATION_2 *cert_data;
    uint8_t *sig_data;
    uint32_t sig_data_size;
    uint8_t *payload_ptr;
    uint64_t payload_size;
    uint32_t attr;
    bool verify_status;
    EFI_STATUS status;
    EFI_SIGNATURE_LIST *cert_list;
    EFI_SIGNATURE_DATA *cert;
    uint64_t index;
    uint64_t cert_count;
    uint32_t kek_data_size;
    uint8_t *new_data;
    uint64_t new_data_size;
    uint8_t *buffer;
    uint64_t length;
    uint8_t *top_level_cert;
    uint64_t top_level_cert_size;
    uint8_t *trusted_cert;
    uint64_t trusted_cert_size;
    uint8_t *signer_certs;
    uint64_t cert_stack_size;
    uint8_t *certs_in_cert_db;
    uint32_t certs_sizein_db;
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    EFI_CERT_DATA *cert_data_ptr;

    //
    // 1. top_level_cert is the top-level issuer certificate in signature signer cert chain
    // 2. trusted_cert is the certificate which firmware trusts. it could be saved in protected
    //     storage or pk payload on pk init
    //
    verify_status = false;
    cert_data = NULL;
    new_data = NULL;
    attr = attributes;
    signer_certs = NULL;
    top_level_cert = NULL;
    certs_in_cert_db = NULL;
    cert_data_ptr = NULL;

    //
    // when the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is
    // set, then the data buffer shall begin with an instance of a complete (and serialized)
    // EFI_VARIABLE_AUTHENTICATION_2 descriptor. the descriptor shall be followed by the new
    // variable value and data_size shall reflect the combined size of the descriptor and the new
    // variable value. the authentication descriptor is not part of the variable data and is not
    // returned by subsequent calls to get_variable().
    //
    cert_data = (EFI_VARIABLE_AUTHENTICATION_2 *) data;

    //
    // verify that pad1, nanosecond, time_zone, daylight and pad2 components of the
    // TimeStamp value are set to zero.
    //
    if ((cert_data->TimeStamp.Pad1 != 0) ||
      (cert_data->TimeStamp.Nanosecond != 0) ||
      (cert_data->TimeStamp.TimeZone != 0) ||
      (cert_data->TimeStamp.Daylight != 0) ||
      (cert_data->TimeStamp.Pad2 != 0)) {
        return EFI_SECURITY_VIOLATION;
    }

    if ((org_time_stamp != NULL) && ((attributes & EFI_VARIABLE_APPEND_WRITE) == 0)) {
        if (auth_compare_time_stamp(&cert_data->TimeStamp, org_time_stamp)) {
            //
            // time_stamp check fail, suspicious replay attack, return EFI_SECURITY_VIOLATION.
            //
            return EFI_SECURITY_VIOLATION;
        }
    }

    //
    // wCertificateType should be WIN_CERT_TYPE_EFI_GUID.
    // cert type should be efi_cert_type_pkcs7_guid.
    //
    if ((cert_data->AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID) ||
      !memcpy(&cert_data->AuthInfo.CertType, &gEfiCertPkcs7Guid, sizeof(EFI_GUID))) {
    //
    // invalid AuthInfo type, return EFI_SECURITY_VIOLATION.
    //
        return EFI_SECURITY_VIOLATION;
    }

    //
    // find out pkcs7 signed_data which follows the EFI_VARIABLE_AUTHENTICATION_2 descriptor.
    // AuthInfo.Hdr.dwLength is the length of the entire certificate, including the length of the header.
    //
    sig_data = cert_data->AuthInfo.CertData;
    sig_data_size = cert_data->AuthInfo.Hdr.dwLength - (uint32_t) (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData));

    //
    // signed_data.digest_algorithms shall contain the digest algorithm used when preparing the
    // signature. only a digest algorithm of sha-256 is accepted.
    //
    //    according to pkcs#7 definition:
    //        signed_data ::= sequence {
    //            version version,
    //            digest_algorithms digest_algorithm_identifiers,
    //            content_info content_info,
    //            .... }
    //    the digest_algorithm_identifiers can be used to determine the hash algorithm 
    //    in variable_authentication_2 descriptor.
    //    this field has the fixed offset (+13) and be calculated based on two bytes of length encoding.
    //
    if ( (attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
        if ( sig_data_size >= (13 + sizeof(SHA256_OID_VAL)) ) {
          if (((*(sig_data + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) || 
               (memcmp(sig_data + 13, &SHA256_OID_VAL, sizeof(SHA256_OID_VAL)) != 0)) {
              return EFI_SECURITY_VIOLATION;
            }
        }
    }

    //
    // find out the new data payload which follows pkcs7 signed_data directly.
    //
    payload_ptr = sig_data + sig_data_size;
    payload_size = data_size - OFFSET_OF_AUTHINFO2_CERT_DATA - (uint64_t) sig_data_size;

    //
    // construct a serialization buffer of the values of the name, vendor_guid and attributes
    // parameters of the set_variable() call and the time_stamp component of the
    // EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable's new value
    // i.e. (name, vendor_guid, attributes, time_stamp, data)
    //
    new_data_size = payload_size + sizeof(EFI_TIME) + sizeof(uint32_t) +
                sizeof(EFI_GUID) + strsize16(name) - sizeof(UTF16);

    //
    // here is to reuse scratch data area(at the end of volatile variable store)
    // to reduce smram consumption for smm variable driver.
    // the scratch buffer is enough to hold the serialized data and safe to use,
    // because it is only used at here to do verification temporarily first
    // and then used in update_variable() for a time based auth variable set.
    //
    new_data = malloc(new_data_size);

    if ( !new_data )
        return EFI_OUT_OF_RESOURCES;

    buffer = new_data;
    length = strlen16(name) * sizeof(UTF16);
    memcpy(buffer, name, length);
    buffer += length;

    length = sizeof(EFI_GUID);
    memcpy(buffer, vendor_guid, length);
    buffer += length;

    length = sizeof(uint32_t);
    memcpy(buffer, &attr, length);
    buffer += length;

    length = sizeof(EFI_TIME);
    memcpy(buffer, &cert_data->TimeStamp, length);
    buffer += length;

    memcpy(buffer, payload_ptr, payload_size);

    if ( auth_var_type == AuthVarTypePk ) {
        //
        // verify that the signature has been made with the current platform key (no chaining for pk).
        // first, get signer's certificates from signed_data.
        //
        verify_status = pkcs7_get_signers(
                         sig_data,
                         sig_data_size,
                         &signer_certs,
                         &cert_stack_size,
                         &top_level_cert,
                         &top_level_cert_size
                         );
        if ( !verify_status )
          goto exit;

        //
        // second, get the current platform key from variable. check whether it's identical with signer's certificates
        // in signed_data. if not, return error immediately.
        //
        status = AuthServiceInternalFindVariable(
                   PK_NAME,
                   &gEfiGlobalVariableGuid,
                   &data,
                   &data_size
                   );
        if ( status )
        {
          verify_status = false;
          goto exit;
        }
        cert_list = (EFI_SIGNATURE_LIST *) data;
        cert = (EFI_SIGNATURE_DATA *) ((uint8_t *) cert_list + sizeof(EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
        if ( (top_level_cert_size != (cert_list->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1))) ||
            (memcmp(cert->SignatureData, top_level_cert, top_level_cert_size) != 0) )
        {
          verify_status = false;
          goto exit;
        }

        //
        // verify pkcs7 signed_data via Pkcs7Verify library.
        //
        verify_status = Pkcs7Verify(
                         sig_data,
                         sig_data_size,
                         top_level_cert,
                         top_level_cert_size,
                         new_data,
                         new_data_size);

    }
    else if ( auth_var_type == AuthVarTypeKek ) {

        //
        // get kek database from variable.
        //
        status = AuthServiceInternalFindVariable (
                   KEK_NAME,
                   &gEfiGlobalVariableGuid,
                   &data,
                   &data_size
                   );
        if ( status )
          return status;

        //
        // ready to verify pkcs7 signed_data. go through kek signature database to find out x.509 cert_list.
        //
        kek_data_size = (uint32_t) data_size;
        cert_list = (EFI_SIGNATURE_LIST *) data;
        while ((kek_data_size > 0) && (kek_data_size >= cert_list->SignatureListSize))
        {
          if ( CompareGuid(&cert_list->SignatureType, &gEfiCertX509Guid) )
          {
            cert = (EFI_SIGNATURE_DATA *) ((uint8_t *) cert_list + sizeof(EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
            cert_count = (cert_list->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - cert_list->SignatureHeaderSize) / cert_list->SignatureSize;
            for ( index = 0; index < cert_count; index++ )
            {
              //
              // iterate each signature data node within this cert_list for a verify
              //
              trusted_cert = cert->SignatureData;
              trusted_cert_size = cert_list->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1);

              //
              // verify pkcs7 signed_data via Pkcs7Verify library.
              //
              verify_status = Pkcs7Verify(
                               sig_data,
                               sig_data_size,
                               trusted_cert,
                               trusted_cert_size,
                               new_data,
                               new_data_size
                               );
              if ( verify_status )
                goto exit;

              cert = (EFI_SIGNATURE_DATA *) ((uint8_t *) cert + cert_list->SignatureSize);
            }
          }
          kek_data_size -= cert_list->SignatureListSize;
          cert_list = (EFI_SIGNATURE_LIST *) ((uint8_t *) cert_list + cert_list->SignatureListSize);
        }
    }
    else if ( auth_var_type == AuthVarTypePriv )
    {
    //
    // process common authenticated variable except pk/kek/db/dbx/dbt.
    // get signer's certificates from signed_data.
    //
    verify_status = pkcs7_get_signers(
                     sig_data,
                     sig_data_size,
                     &signer_certs,
                     &cert_stack_size,
                     &top_level_cert,
                     &top_level_cert_size
                     );
    if ( !verify_status )
      goto exit;

    //
    // get previously stored signer's certificates from certdb or certdbv for existing
    // variable. check whether they are identical with signer's certificates
    // in signed_data. if not, return error immediately.
    //
    if ( org_time_stamp != NULL )
    {
      verify_status = false;

      status = GetCertsFromDb(name, vendor_guid,
                                 attributes, &certs_in_cert_db,
                                 &certs_sizein_db);

      if ( status )
        goto exit;

      if ( certs_sizein_db == SHA256_DIGEST_SIZE )
      {
        //
        // check hash of signer cert common_name + top-level issuer tbs_certificate against data in cert_db
        //
        cert_data_ptr = (EFI_CERT_DATA *)(signer_certs + 1);
        status = CalculatePrivAuthVarSignChainSha256Digest(
                   cert_data_ptr->CertDataBuffer,
                   ReadUnaligned32 ((uint32_t *)&(cert_data_ptr->CertDataLength)),
                   top_level_cert,
                   top_level_cert_size,
                   sha256_digest
               );
        if ( status || memcmp(sha256_digest, certs_in_cert_db, certs_sizein_db) != 0)
          goto exit;
      }
      else
      {
         //
         // keep backward compatible with previous solution which saves whole signer certs stack in cert_db
         //
         if ( (cert_stack_size != certs_sizein_db) ||
             (memcmp (signer_certs, certs_in_cert_db, certs_sizein_db) != 0) )
              goto exit;
      }
    }

    verify_status = Pkcs7Verify(
                     sig_data,
                     sig_data_size,
                     top_level_cert,
                     top_level_cert_size,
                     new_data,
                     new_data_size
                     );
    if ( !verify_status )
      goto exit;

    if ( (org_time_stamp == NULL) && (payload_size != 0) )
    {
      //
      // when adding a new common authenticated variable, always save hash of cn of signer cert + tbs_certificate of top-level issuer
      //
      cert_data_ptr = (EFI_CERT_DATA *)(signer_certs + 1);
      status = InsertCertsToDb(
                 name,
                 vendor_guid,
                 attributes,
                 cert_data_ptr->CertDataBuffer,
                 ReadUnaligned32 ((uint32_t *)&(cert_data_ptr->CertDataLength)),
                 top_level_cert,
                 top_level_cert_size
                 );
      if ( status )
      {
        verify_status = false;
        goto exit;
      }
    }
    }
    else if (auth_var_type == AuthVarTypePayload)
    {
        cert_list = (EFI_SIGNATURE_LIST *) payload_ptr;
        cert = (EFI_SIGNATURE_DATA *) ((uint8_t *) cert_list + sizeof(EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
        trusted_cert     = cert->SignatureData;
        trusted_cert_size = cert_list->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1);
        //
        // verify pkcs7 signed_data via Pkcs7Verify library.
        //
        verify_status = Pkcs7Verify(
                         sig_data,
                         sig_data_size,
                         trusted_cert,
                         trusted_cert_size,
                         new_data,
                         new_data_size);
    }
    else
    {
        return EFI_SECURITY_VIOLATION;
    }

exit:

    if ( auth_var_type == AuthVarTypePk || auth_var_type == AuthVarTypePriv )
    {
        Pkcs7FreeSigners (top_level_cert);
        Pkcs7FreeSigners (signer_certs);
    }

    if ( !verify_status )
    {
        return EFI_SECURITY_VIOLATION;
    }

    status = check_signature_list_format(name, vendor_guid, payload_ptr, payload_size);

    if ( status )
    {
        return status;
    }

    *var_payload_ptr = payload_ptr;
    *var_payload_size = payload_size;

    return EFI_SUCCESS;
}

