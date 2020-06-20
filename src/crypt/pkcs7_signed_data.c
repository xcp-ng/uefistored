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
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>

#include "uefitypes.h"

int PKCS7_final_nodata(PKCS7 *p7, int flags);

uint64_t certificate_get_signers(const unsigned char *buf, size_t buf_sz,
                                 PKCS7 **pkcs7, STACK_OF(X509) **signer_stack_out)

{
    PKCS7 *pkcs7_obj;
    STACK_OF(X509) *signer_stack;

    pkcs7_obj = d2i_PKCS7(NULL, &buf, buf_sz);

    if ( !pkcs7_obj )
        return EFI_SECURITY_VIOLATION;

    if ( OBJ_obj2nid(pkcs7_obj->type) != NID_pkcs7_signed )
    {
        PKCS7_free(*pkcs7);
        return EFI_SECURITY_VIOLATION;
    }

    signer_stack = PKCS7_get0_signers(*pkcs7, NULL, PKCS7_BINARY);
    if ( !signer_stack )
    {
        PKCS7_free(*pkcs7);
        return EFI_SECURITY_VIOLATION;
    }

    *pkcs7 = pkcs7_obj;
    *signer_stack_out = signer_stack;

    return 0;
}

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509_STORE *ts;
    X509_OBJECT *match, *x;
    int ret, num, i;
    void *val;
  
    ret = X509_STORE_CTX_get_error(ctx);

    if ( ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
         ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT )
    {
        x = X509_OBJECT_new();
        if ( !x )
          return 0;

        X509_OBJECT_set1_X509(x, X509_STORE_CTX_get_current_cert(ctx));

#if OPENSSL_VERSION_NUMBER < 0x10100005L
        CRYPTO_w_lock(0xb);
#endif
        ts = X509_STORE_CTX_get0_store(ctx);
        match = X509_OBJECT_retrieve_match(X509_STORE_get0_objects(ts), x);
        if ( !match )
        {
            ret = 0;
            goto unlock;
        }

        num = sk_X509_num(X509_STORE_CTX_get0_chain(ctx));

        if ( ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY )
        {
            while ( i != num && 0 < num )
            {
                val = sk_X509_value(X509_STORE_CTX_get0_chain(ctx), i);
                X509_OBJECT_set1_X509(x, val);
//                *(void **)&x->data = val;
                match = X509_OBJECT_retrieve_match(X509_STORE_get0_objects(ts), x);
                if ( !match )
                    goto unlock;
                i++;

            }
        }
    }

    if ( ret == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE ||
       ret == X509_V_ERR_CERT_UNTRUSTED || 
       ret < X509_V_ERR_CRL_NOT_YET_VALID )
    ret = 1;

unlock:
#if OPENSSL_VERSION_NUMBER < 0x10100005L
    CRYPTO_w_unlock(0xb);
#endif

    free(x);
    return ret;
}

uint64_t verify_authvar(unsigned char *dest, int dest_sz,
                   X509 *x509_cert, const unsigned char *src, size_t src_sz)
{
    uint64_t ret;
    PKCS7 *p7;
    X509_STORE *ctx = NULL;
    BIO *b = NULL;

    p7 = d2i_PKCS7(NULL, &src, src_sz);
    if ( !p7 || (OBJ_obj2nid(p7->type) != NID_pkcs7_signed) )
    {
        ret = EFI_SECURITY_VIOLATION;
        goto err;
    }

    ctx = X509_STORE_new();
    if ( !ctx )
    {
        ret = EFI_DEVICE_ERROR;
        goto err;
    }

    X509_STORE_set_verify_cb(ctx, verify_callback);

    ret = X509_STORE_add_cert(ctx, x509_cert);
    if ( !ret )
    {
        ret = EFI_SECURITY_VIOLATION;
        goto err;
    }

    b = BIO_new(BIO_s_mem());
    if ( !b )
    {
        ret = EFI_SECURITY_VIOLATION;
        goto err;
    }

    ret = BIO_write(b, dest, (int)dest_sz);
    if ( ret != src_sz )
    {
        ret = EFI_SECURITY_VIOLATION;
        goto err;
    }

    X509_STORE_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    X509_STORE_set_purpose(ctx, X509_PURPOSE_ANY);

    ret = PKCS7_verify(p7, NULL, ctx, b, NULL, 0x80);
    if ( ret != 1 )
    {
        ret = EFI_SECURITY_VIOLATION;
        goto err;
    }

    ret = 0;

err:
    BIO_free(b);
    X509_STORE_free(ctx);
    PKCS7_free(p7);
    return ret;
}

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

#if 0
  if ( EVP_add_digest(EVP_md5()) == 0 )
    goto err;

  if ( EVP_add_digest(EVP_sha1()) == 0 )
    goto err;
#endif

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


  //pkcs7 = PKCS7_sign(sign_cert, key,
  //                   other_certs, p7_data,
  //                   PKCS7_BINARY | PKCS7_NOATTR | PKCS7_DETACHED);
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
