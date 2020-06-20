unsigned long verify_callback(unsigned int ok, X509_STORE_CTX *x509_store)

{
    X509_OBJECT *match;
    X509_OBJECT *x;
    int ret;
    int num;
    void *val;
    int i;
  
    ret = X509_STORE_CTX_get_error(x509_store);

    if ( ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
         ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT )
    {
        x = malloc(0x10);
        if ( !x )
          return 0;

        
        x->type = X509_LU_X509;
        x->data = X509_STORE_CTX_get_current_cert(x509_store);;

        CRYPTO_w_lock(0xb);

        match = X509_OBJECT_retrieve_match(x509_store->ctx->objs, x);
        if ( !match )
        {
            ret = 0;
            goto unlock;
        }

        num = sk_num((_STACK *)x509_store->chain);

        if ( ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY )
        {
            while ( i != num && 0 < num )
            {
                val = sk_value((_STACK *)x509_store->chain, i);
                *(void **)&x->data = val;
                match = X509_OBJECT_retrieve_match(x509_store->ctx->objs, x);
                if ( !match )
                    goto unlock;
                i++;

            }
        }
    }
  }

  if ( ret == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE ||
       ret == X509_V_ERR_CERT_UNTRUSTED || 
       ret < X509_V_ERR_CRL_NOT_YET_VALID )
    ret = 1;

unlock:
  CRYPTO_w_unlock(0xb);

err:
  free(x);
  return ret;
}

int verify_authvar(unsigned char *dest, int dest_sz,
                   X509 *x509_cert, void *src, size_t src_sz)
{
    int ret;
    PKCS7 *p7;
    X509_STORE *ctx = NULL;
    BIO *b = NULL;
    void *p;

    p7 = d2i_PKCS7(NULL, &dest, dest_sz);
    if ( !p7 || (OBJ_obj2nid(p7->type) != 0x16) )
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

    ret = BIO_write(b, src, (int)src_sz);
    if ( ret != src_sz )
    {
        ret = EFI_SECURITY_VIOLATION;
        goto err;
    }

    X509_STORE_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    X509_STORE_set_purpose(ctx, X509_STORE_CTX_set_purpose);

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
