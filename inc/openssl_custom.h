#ifndef __H_OPENSSL_CUSTOM__
#define __H_OPENSSL_CUSTOM__

#include <openssl/rsa.h>
#include <openssl/objects.h>

#if OPENSSL_VERSION_NUMBER < 0x10100006L

STACK_OF(X509) *X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *CertCtx)
{
    return CertCtx->untrusted;
}

#endif

#endif // __H_OPENSSL_CUSTOM__
