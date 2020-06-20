#ifndef __H_PKCS7_SIGNED_DATA_
#define __H_PKCS7_SIGNED_DATA_

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>


int PKCS7_final_nodata(PKCS7 *p7, int flags);
PKCS7 *PKCS7_sign_nodata(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, int flags);

#endif // __H_PKCS7_SIGNED_DATA_
