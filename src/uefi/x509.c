/** @file
  X.509 Certificate Handler Wrapper Implementation over OpenSSL.

Copyright (c) 2010 - 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <stdint.h>

#include "uefi/types.h"
#include "uefi/x509.h"

/**
  Construct a X509 object from DER-encoded certificate data.

  If Cert is NULL, then return false.
  If SingleX509Cert is NULL, then return false.

  @param[in]  Cert            Pointer to the DER-encoded certificate data.
  @param[in]  CertSize        The size of certificate data in bytes.
  @param[out] SingleX509Cert  The generated X509 object.

  @retval     true            The X509 object generation succeeded.
  @retval     false           The operation failed.

**/
bool X509ConstructCertificate (
   const uint8_t  *Cert,
   uint64_t        CertSize,
  uint8_t        **SingleX509Cert
  )
{
  X509         *X509Cert;
  const uint8_t  *Temp;

  //
  // Check input parameters.
  //
  if (Cert == NULL || SingleX509Cert == NULL || CertSize > INT_MAX) {
    return false;
  }

  //
  // Read DER-encoded X509 Certificate and Construct X509 object.
  //
  Temp     = Cert;
  X509Cert = d2i_X509 (NULL, &Temp, (long) CertSize);
  if (X509Cert == NULL) {
    return false;
  }

  *SingleX509Cert = (uint8_t *) X509Cert;

  return true;
}

/**
  Construct a X509 stack object from a list of DER-encoded certificate data.

  If X509Stack is NULL, then return false.

  @param[in, out]  X509Stack  On input, pointer to an existing or NULL X509 stack object.
                              On output, pointer to the X509 stack object with new
                              inserted X509 certificate.
  @param           ...        A list of DER-encoded single certificate data followed
                              by certificate size. A NULL terminates the list. The
                              pairs are the arguments to X509ConstructCertificate().

  @retval     true            The X509 stack construction succeeded.
  @retval     false           The construction operation failed.

**/
bool X509ConstructCertificateStack (
 uint8_t  **X509Stack,
  ...
  )
{
  uint8_t           *Cert;
  uint64_t           CertSize;
  X509            *X509Cert;
  STACK_OF(X509)  *CertStack;
  bool         Status;
  va_list         Args;
  uint64_t           Index;

  //
  // Check input parameters.
  //
  if (X509Stack == NULL) {
    return false;
  }

  Status = false;

  //
  // Initialize X509 stack object.
  //
  CertStack = (STACK_OF(X509) *) (*X509Stack);
  if (CertStack == NULL) {
    CertStack = sk_X509_new_null ();
    if (CertStack == NULL) {
      return Status;
    }
  }

  va_start (Args, X509Stack);

  for (Index = 0; ; Index++) {
    //
    // If Cert is NULL, then it is the end of the list.
    //
    Cert = va_arg (Args, uint8_t *);
    if (Cert == NULL) {
      break;
    }

    CertSize = va_arg (Args, uint64_t);
    if (CertSize == 0) {
      break;
    }

    //
    // Construct X509 Object from the given DER-encoded certificate data.
    //
    X509Cert = NULL;
    Status = X509ConstructCertificate (
               (const uint8_t *) Cert,
               CertSize,
               (uint8_t **) &X509Cert
               );
    if (!Status) {
      if (X509Cert != NULL) {
        X509_free (X509Cert);
      }
      break;
    }

    //
    // Insert the new X509 object into X509 stack object.
    //
    sk_X509_push (CertStack, X509Cert);
  }

  va_end (Args);

  if (!Status) {
    sk_X509_pop_free (CertStack, X509_free);
  } else {
    *X509Stack = (uint8_t *) CertStack;
  }

  return Status;
}

/**
  Release the specified X509 object.

  If X509Cert is NULL, then return false.

  @param[in]  X509Cert  Pointer to the X509 object to be released.

**/
void X509Free (
  void  *X509Cert
  )
{
  //
  // Check input parameters.
  //
  if (X509Cert == NULL) {
    return;
  }

  //
  // Free OpenSSL X509 object.
  //
  X509_free ((X509 *) X509Cert);
}

/**
  Release the specified X509 stack object.

  If X509Stack is NULL, then return false.

  @param[in]  X509Stack  Pointer to the X509 stack object to be released.

**/
void X509StackFree (
  void  *X509Stack
  )
{
  //
  // Check input parameters.
  //
  if (X509Stack == NULL) {
    return;
  }

  //
  // Free OpenSSL X509 stack object.
  //
  sk_X509_pop_free ((STACK_OF(X509) *) X509Stack, X509_free);
}

/**
  Retrieve the subject bytes from one X.509 certificate.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     CertSubject  Pointer to the retrieved certificate subject bytes.
  @param[in, out] SubjectSize  The size in bytes of the CertSubject buffer on input,
                               and the size of buffer returned CertSubject on output.

  If Cert is NULL, then return false.
  If SubjectSize is NULL, then return false.

  @retval  true   The certificate subject retrieved successfully.
  @retval  false  Invalid certificate, or the SubjectSize is too small for the result.
                  The SubjectSize will be updated with the required size.

**/
bool X509GetSubjectName (
      const uint8_t  *Cert,
      uint64_t        CertSize,
     uint8_t        *CertSubject,
 uint64_t        *SubjectSize
  )
{
  bool    Status;
  X509       *X509Cert;
  X509_NAME  *X509Name;
  uint64_t      X509NameSize;

  //
  // Check input parameters.
  //
  if (Cert == NULL || SubjectSize == NULL) {
    return false;
  }

  X509Cert = NULL;

  //
  // Read DER-encoded X509 Certificate and Construct X509 object.
  //
  Status = X509ConstructCertificate (Cert, CertSize, (uint8_t **) &X509Cert);
  if ((X509Cert == NULL) || (!Status)) {
    Status = false;
    goto _Exit;
  }

  Status = false;

  //
  // Retrieve subject name from certificate object.
  //
  X509Name = X509_get_subject_name (X509Cert);
  if (X509Name == NULL) {
    goto _Exit;
  }

  X509NameSize = i2d_X509_NAME(X509Name, NULL);
  if (*SubjectSize < X509NameSize) {
    *SubjectSize = X509NameSize;
    goto _Exit;
  }
  *SubjectSize = X509NameSize;
  if (CertSubject != NULL) {
    i2d_X509_NAME(X509Name, &CertSubject);
    Status = true;
  }

_Exit:
  //
  // Release Resources.
  //
  if (X509Cert != NULL) {
    X509_free (X509Cert);
  }

  return Status;
}

/**
  Retrieve the common name (CN) string from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     CommonName       Buffer to contain the retrieved certificate common
                                   name string. At most CommonNameSize bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  CommonNameSize   The size in bytes of the CommonName buffer on input,
                                   and the size of buffer returned CommonName on output.
                                   If CommonName is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate CommonName retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If CommonNameSize is NULL.
                                   If CommonName is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no CommonName entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the CommonName is NULL. The required buffer size
                                   (including the final null) is returned in the 
                                   CommonNameSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
RETURN_STATUS X509GetCommonName (
     const uint8_t *Cert,
     uint64_t CertSize,
     char *CommonName,
     uint64_t *CommonNameSize
  )
{
  RETURN_STATUS  ReturnStatus;
  bool        Status;
  X509           *X509Cert;
  X509_NAME      *X509Name;
  INTN           Length;

  ReturnStatus = RETURN_INVALID_PARAMETER;

  //
  // Check input parameters.
  //
  if ((Cert == NULL) || (CertSize > INT_MAX) || (CommonNameSize == NULL)) {
    return ReturnStatus;
  }
  if ((CommonName != NULL) && (*CommonNameSize == 0)) {
    return ReturnStatus;
  }

  X509Cert = NULL;
  //
  // Read DER-encoded X509 Certificate and Construct X509 object.
  //
  Status = X509ConstructCertificate (Cert, CertSize, (uint8_t **) &X509Cert);
  if ((X509Cert == NULL) || (!Status)) {
    //
    // Invalid X.509 Certificate
    //
    goto _Exit;
  }

  Status = false;

  //
  // Retrieve subject name from certificate object.
  //
  X509Name = X509_get_subject_name (X509Cert);
  if (X509Name == NULL) {
    //
    // Fail to retrieve subject name content
    //
    goto _Exit;
  }

  //
  // Retrieve the CommonName information from X.509 Subject
  //
  Length = (INTN) X509_NAME_get_text_by_NID (X509Name, NID_commonName, CommonName, (int)(*CommonNameSize));
  if (Length < 0) {
    //
    // No CommonName entry exists in X509_NAME object
    //
    *CommonNameSize = 0;
    ReturnStatus    = RETURN_NOT_FOUND;
    goto _Exit;
  }

  *CommonNameSize = (uint64_t)(Length + 1);
  if (CommonName == NULL) {
    ReturnStatus = RETURN_BUFFER_TOO_SMALL;
  } else {
    ReturnStatus = RETURN_SUCCESS;
  }

_Exit:
  //
  // Release Resources.
  //
  if (X509Cert != NULL) {
    X509_free (X509Cert);
  }

  return ReturnStatus;
}

/**
  Retrieve the RSA Public Key from one DER-encoded X509 certificate.

  @param[in]  Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  CertSize     Size of the X509 certificate in bytes.
  @param[out] RsaContext   Pointer to new-generated RSA context which contain the retrieved
                           RSA public key component. Use RsaFree() function to free the
                           resource.

  If Cert is NULL, then return false.
  If RsaContext is NULL, then return false.

  @retval  true   RSA Public Key was retrieved successfully.
  @retval  false  Fail to retrieve RSA public key from X509 certificate.

**/
bool RsaGetPublicKeyFromX509 (
  const uint8_t  *Cert,
  uint64_t        CertSize,
  void         **RsaContext
  )
{
  bool   Status;
  EVP_PKEY  *Pkey;
  X509      *X509Cert;

  //
  // Check input parameters.
  //
  if (Cert == NULL || RsaContext == NULL) {
    return false;
  }

  Pkey     = NULL;
  X509Cert = NULL;

  //
  // Read DER-encoded X509 Certificate and Construct X509 object.
  //
  Status = X509ConstructCertificate (Cert, CertSize, (uint8_t **) &X509Cert);
  if ((X509Cert == NULL) || (!Status)) {
    Status = false;
    goto _Exit;
  }

  Status = false;

  //
  // Retrieve and check EVP_PKEY data from X509 Certificate.
  //
  Pkey = X509_get_pubkey (X509Cert);
  if ((Pkey == NULL) || (EVP_PKEY_id (Pkey) != EVP_PKEY_RSA)) {
    goto _Exit;
  }

  //
  // Duplicate RSA Context from the retrieved EVP_PKEY.
  //
  if ((*RsaContext = RSAPublicKey_dup (EVP_PKEY_get0_RSA (Pkey))) != NULL) {
    Status = true;
  }

_Exit:
  //
  // Release Resources.
  //
  if (X509Cert != NULL) {
    X509_free (X509Cert);
  }

  if (Pkey != NULL) {
    EVP_PKEY_free (Pkey);
  }

  return Status;
}

/**
  Verify one X509 certificate was issued by the trusted CA.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate to be verified.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[in]      CACert       Pointer to the DER-encoded trusted CA certificate.
  @param[in]      CACertSize   Size of the CA Certificate in bytes.

  If Cert is NULL, then return false.
  If CACert is NULL, then return false.

  @retval  true   The certificate was issued by the trusted CA.
  @retval  false  Invalid certificate or the certificate was not issued by the given
                  trusted CA.

**/
bool
X509VerifyCert (
  const uint8_t  *Cert,
  uint64_t        CertSize,
  const uint8_t  *CACert,
  uint64_t        CACertSize
  )
{
  bool         Status;
  X509            *X509Cert;
  X509            *X509CACert;
  X509_STORE      *CertStore;
  X509_STORE_CTX  *CertCtx;

  //
  // Check input parameters.
  //
  if (Cert == NULL || CACert == NULL) {
    return false;
  }

  Status     = false;
  X509Cert   = NULL;
  X509CACert = NULL;
  CertStore  = NULL;
  CertCtx    = NULL;

  //
  // Register & Initialize necessary digest algorithms for certificate verification.
  //
  if (EVP_add_digest (EVP_md5 ()) == 0) {
    goto _Exit;
  }
  if (EVP_add_digest (EVP_sha1 ()) == 0) {
    goto _Exit;
  }
  if (EVP_add_digest (EVP_sha256 ()) == 0) {
    goto _Exit;
  }

  //
  // Read DER-encoded certificate to be verified and Construct X509 object.
  //
  Status = X509ConstructCertificate (Cert, CertSize, (uint8_t **) &X509Cert);
  if ((X509Cert == NULL) || (!Status)) {
    Status = false;
    goto _Exit;
  }

  //
  // Read DER-encoded root certificate and Construct X509 object.
  //
  Status = X509ConstructCertificate (CACert, CACertSize, (uint8_t **) &X509CACert);
  if ((X509CACert == NULL) || (!Status)) {
    Status = false;
    goto _Exit;
  }

  Status = false;

  //
  // Set up X509 Store for trusted certificate.
  //
  CertStore = X509_STORE_new ();
  if (CertStore == NULL) {
    goto _Exit;
  }
  if (!(X509_STORE_add_cert (CertStore, X509CACert))) {
    goto _Exit;
  }

  //
  // Allow partial certificate chains, terminated by a non-self-signed but
  // still trusted intermediate certificate. Also disable time checks.
  //
  X509_STORE_set_flags (CertStore,
                        X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_NO_CHECK_TIME);

  //
  // Set up X509_STORE_CTX for the subsequent verification operation.
  //
  CertCtx = X509_STORE_CTX_new ();
  if (CertCtx == NULL) {
    goto _Exit;
  }
  if (!X509_STORE_CTX_init (CertCtx, CertStore, X509Cert, NULL)) {
    goto _Exit;
  }

  //
  // X509 Certificate Verification.
  //
  Status = (bool) X509_verify_cert (CertCtx);
  X509_STORE_CTX_cleanup (CertCtx);

_Exit:
  //
  // Release Resources.
  //
  if (X509Cert != NULL) {
    X509_free (X509Cert);
  }

  if (X509CACert != NULL) {
    X509_free (X509CACert);
  }

  if (CertStore != NULL) {
    X509_STORE_free (CertStore);
  }

  X509_STORE_CTX_free (CertCtx);

  return Status;
}

/**
  Retrieve the TBSCertificate from one given X.509 certificate.

  @param[in]      Cert         Pointer to the given DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     TBSCert      DER-Encoded To-Be-Signed certificate.
  @param[out]     TBSCertSize  Size of the TBS certificate in bytes.

  If Cert is NULL, then return false.
  If TBSCert is NULL, then return false.
  If TBSCertSize is NULL, then return false.

  @retval  true   The TBSCertificate was retrieved successfully.
  @retval  false  Invalid X.509 certificate.

**/
bool X509GetTBSCert (
  const uint8_t  *Cert,
  uint64_t        CertSize,
 uint8_t        **TBSCert,
 uint64_t        *TBSCertSize
  )
{
  const uint8_t  *Temp;
  uint32_t       Asn1Tag;
  uint32_t       ObjClass;
  uint64_t        Length;

  //
  // Check input parameters.
  //
  if ((Cert == NULL) || (TBSCert == NULL) ||
      (TBSCertSize == NULL) || (CertSize > INT_MAX)) {
    return false;
  }

  //
  // An X.509 Certificate is: (defined in RFC3280)
  //   Certificate  ::=  SEQUENCE  {
  //     tbsCertificate       TBSCertificate,
  //     signatureAlgorithm   AlgorithmIdentifier,
  //     signature            BIT STRING }
  //
  // and
  //
  //  TBSCertificate  ::=  SEQUENCE  {
  //    version         [0]  Version DEFAULT v1,
  //    ...
  //    }
  //
  // So we can just ASN1-parse the x.509 DER-encoded data. If we strip
  // the first SEQUENCE, the second SEQUENCE is the TBSCertificate.
  //
  Temp   = Cert;
  Length = 0;
  ASN1_get_object (&Temp, (long *)&Length, (int *)&Asn1Tag, (int *)&ObjClass, (long)CertSize);

  if (Asn1Tag != V_ASN1_SEQUENCE) {
    return false;
  }

  *TBSCert = (uint8_t *)Temp;

  ASN1_get_object (&Temp, (long *)&Length, (int *)&Asn1Tag, (int *)&ObjClass, (long)Length);
  //
  // Verify the parsed TBSCertificate is one correct SEQUENCE data.
  //
  if (Asn1Tag != V_ASN1_SEQUENCE) {
    return false;
  }

  *TBSCertSize = Length + (Temp - *TBSCert);

  return true;
}
