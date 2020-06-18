#include "uefitypes.h"
#include "uefi_guids.h"
#include <stdio.h>

#include <assert.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>

#include "uefitypes.h"

int PKCS7_final_nodata(PKCS7 *p7, int flags);

PKCS7 *PKCS7_sign_nodata(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, int flags)
{
    PKCS7 *p7;
    int i;

    if ((p7 = PKCS7_new()) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        goto err;

    if (!PKCS7_content_new(p7, NID_pkcs7_data))
        goto err;

    if (pkey && !PKCS7_sign_add_signer(p7, signcert, pkey, NULL, flags)) {
        PKCS7err(PKCS7_F_PKCS7_SIGN, PKCS7_R_PKCS7_ADD_SIGNER_ERROR);
        goto err;
    }

    if (!(flags & PKCS7_NOCERTS)) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            if (!PKCS7_add_certificate(p7, sk_X509_value(certs, i)))
                goto err;
        }
    }

    if (flags & PKCS7_DETACHED)
        PKCS7_set_detached(p7, 1);

    if (flags & (PKCS7_STREAM | PKCS7_PARTIAL))
        return p7;

    if (PKCS7_final_nodata(p7, flags))
        return p7;

err:
    PKCS7_free(p7);
    return NULL;
}

int PKCS7_final_nodata(PKCS7 *p7, int flags)
{
    BIO *p7bio;
    int ret = 0;

    if ((p7bio = PKCS7_dataInit(p7, NULL)) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_FINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    //SMIME_crlf_copy(data, p7bio, flags);

    (void)BIO_flush(p7bio);

    if (!PKCS7_dataFinal(p7, p7bio)) {
        PKCS7err(PKCS7_F_PKCS7_FINAL, PKCS7_R_PKCS7_DATASIGN);
        goto err;
    }

    ret = 1;

 err:
    BIO_free_all(p7bio);

    return ret;

}

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

static UTF16 name[] = {'F', 'o', 'o', 0 };
static UTF16 data[] = {'B', 'a', 'r', 0 };

int sha256_hash(unsigned char hash[SHA256_DIGEST_LENGTH], char *string)
{
    SHA256_CTX sha256;

    if ( SHA256_Init(&sha256) != 1)
        return -1;

    if ( SHA256_Update(&sha256, string, strlen(string)) != 1 )
        return -1;

    if ( SHA256_Final(hash, &sha256) != 1 )
        return -1;

    return 0;
}

EVP_PKEY *get_rsa_key(void)
{
    BIGNUM *bn;
    EVP_PKEY *pk;
    RSA *rsa;

    rsa = RSA_new();
    pk = EVP_PKEY_new();

    bn = BN_new();
    BN_set_word(bn, RSA_F4);

    if ( RSA_generate_key_ex( rsa, 2048, bn, NULL) != 1 )
    {
        RSA_free(rsa);
        EVP_PKEY_free(pk);
        return NULL;
    }

    EVP_PKEY_assign_RSA(pk, rsa);

    return pk;
}

int
pkcs7_sign(
    uint8_t *in_data,
    uint32_t in_data_size,
    uint8_t *sign_cert,
    uint8_t *other_certs,
    uint8_t **signed_data,
    uint32_t *signed_data_size
  )
{
  int status;
  EVP_PKEY *key = NULL;
  BIO *data_bio = NULL;
  PKCS7 *pkcs7 = NULL;
  uint8_t *rsa_context;
  uint8_t *p7_data;
  uint32_t p7_data_size;
  uint8_t *tmp;

#if 0
  if (in_data == NULL || sign_cert == NULL || signed_data == NULL ||
      signed_data_size == NULL || in_data_size > INT_MAX) {
    return -1;
  }
#endif

  status = -1;

  if ( EVP_add_digest(EVP_md5()) == 0 )
    goto err;

  if ( EVP_add_digest(EVP_sha1()) == 0 )
    goto err;

  if ( EVP_add_digest(EVP_sha256()) == 0 )
    goto err;

  data_bio = BIO_new(BIO_s_mem());
  if ( data_bio == NULL )
    goto err;

#if 0
  if ( BIO_write(data_bio, in_data, (int)in_data_size) <= 0 )
    goto err;
  printf("%s:%d\n", __func__, __LINE__);
#endif

  pkcs7 = PKCS7_sign_nodata((X509*)sign_cert, key,
            (STACK_OF(X509)*)other_certs,
            PKCS7_BINARY | PKCS7_NOATTR | PKCS7_DETACHED);
  if ( pkcs7 == NULL )
    goto err;

  //
  // Convert PKCS#7 signedData structure into DER-encoded buffer.
  //
  p7_data_size = i2d_PKCS7(pkcs7, NULL);
  if ( p7_data_size <= 19 )
    goto err;

  p7_data = malloc(p7_data_size);
  if ( p7_data == NULL )
    goto err;

  tmp = p7_data;
  p7_data_size = i2d_PKCS7(pkcs7, (unsigned char **)&tmp);
  assert(p7_data_size > 19);

  //
  // Strip ContentInfo to content only for signeddata. The data be trimmed off
  // is totally 19 bytes.
  //
  *signed_data_size = p7_data_size - 19;
  *signed_data = malloc(*signed_data_size);
  if ( *signed_data == NULL ) {
    OPENSSL_free(p7_data);
    goto err;
  }

  memcpy(*signed_data, p7_data + 19, *signed_data_size);

  OPENSSL_free(p7_data);

  status = 0;

err:
  if ( key != NULL )
    EVP_PKEY_free(key);

  if ( data_bio != NULL )
    BIO_free(data_bio);

  if ( pkcs7 != NULL )
    PKCS7_free(pkcs7);

  return status;
}

int main(void)
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

    printf("%s:%d\n", __func__, __LINE__);
    pkey = get_rsa_key();
    if ( !pkey )
    {
        fprintf(stderr, "No key!\n");
        return -1;
    }

    printf("%s:%d\n", __func__, __LINE__);
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
    EVP_PKEY_free(pkey);
    printf("%s:%d\n", __func__, __LINE__);

    return 0;
}
