uint64_t DAT_0040a9c0 = 0x07010DF78648862A;

uint8_t mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

uint8_t FUN_00403720(uint8_t *param_1,uint8_t *param_2)

{
    uint8_t uVar1;
    undefined uVar2;
    bool bVar3;

    uVar1 = *param_2;
    uVar2 = (undefined)(uVar1 >> 8);
    bVar3 = *param_1 < uVar1;

    /* Is the first byte equal? */
    if (*param_1 == uVar1)
    {
        uVar2 = (undefined)((uVar1 & 0xff00) >> 8);
        bVar3 = *(byte *)(param_1 + 1) < *(byte *)(param_2 + 1);
        if (*(byte *)(param_1 + 1) == *(byte *)(param_2 + 1))
        {
            bVar3 = *(byte *)((long)param_1 + 3) < *(byte *)((long)param_2 + 3);
            if (*((long)param_1 + 3) == *((long)param_2 + 3))
            {
                bVar3 = *(param_1 + 2) < *(param_2 + 2);
                if (*(param_1 + 2) == *(param_2 + 2))
                {
                    bVar3 = *((long)param_1 + 5) < *((long)param_2 + 5);
                    if (*((long)param_1 + 5) == *((long)param_2 + 5))
                    {
                        return uVar1 & 0xff00 |
                            (uint8_t)(*(param_1 + 3) <= *(param_2 + 3) &&
                            *(param_2 + 3) != *(param_1 + 3));
                    }
                }
            }
        }
    }
    return CONCAT11(uVar2,bVar3);
}

uint64_t get_variable_data(void *varname,void *varname_sz, void **out,void **outsz)
{
    variable_t *variable;


    variable = find_variable(varname, variables, MAX_VAR_COUNT);

    if ( !variable )
        return EFI_NOT_FOUND;

    *out = malloc(variable->datasz);

    if ( *out == NULL )
        return EFI_DEVICE_ERROR;

    memcpy(*out, variable->data, variable->datasz);
    *outsz = variable->datasz;
    return 0;
}


unsigned char *encode_X509_der(X509 *cert, int *outlen)
{
    int len;
    unsigned char *result;

    len = i2d_X509(cert, NULL);
    result = malloc(len);

    if ( result )
    {
        i2d_X509(cert, &result);
    }

    *outlen = len;

    return result;
}


uint64_t do_sha_hash(unsigned char *ciphertext, char *data, char *plaintext, size_t plength)
{
    int ret;
    size_t len = 0;
    SHA256 *sha256;
    char *ppuVar20;
    char cVar5;

    ret = SHA256_Init(&sha256);
    if (ret != 1)
        return EFI_DEVICE_ERROR;

    len = strlen(plaintext);

    if ( SHA256_Update(&sha256, plaintext, len) != 1 )
        return EFI_DEVICE_ERROR;

    if ( SHA256_Update(&sha256, data, (size_t)plength) != 1 )
        return EFI_DEVICE_ERROR;

    if ( SHA256_Final(ciphertext, &sha256) != 1 )
        return EFI_DEVICE_ERROR;

    return EFI_SUCCESS;
}

void * process_x509(undefined *param_1, long param_2, astruct_6 *param_3, ulong total_size_param,
                   undefined8 *param_5,uint param_6,char param_7,long param_8,int param_9,
                   undefined8 *out_ptr,size_t *out_sz,uchar *sha256_cipher, EFI_TIME **timestamp)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  size_t len;
  SHA256 *sha256;
  char cVar5;
  int iVar6;
  int count;
  void *x509_cert;
  int x509_len;  
  char *x509_der;  
  long lVar7;
  X509 *a;
  X509_NAME *name;
  uchar *data;
  size_t cert_size;
  size_t body_size;
  ulong header_size;
  void *__s1;
  void *__s2;
  void *body;
  undefined8 *ptr;
  undefined *puVar18;
  uchar **ppuVar20;
  astruct_2 *dest;
  void *status;
  uchar *plength;
  size_t src_sz;
  undefined8 *src;
  int ptag;
  int pclass;
  int omax;
  void *variable_data;
  _STACK *signer_stack;
  PKCS7 *pkcs7;
  long plength;
  uchar *pp;
  void *hash_cipher;
  uchar *local_b8 [17];
  uchar *x509_cert_buf;
  astruct_6 *tmp_struct6;
  
  variable_data = NULL;
  signer_stack = NULL;
  pkcs7 = NULL;

  if ( total_size_param < 0x28 )
    return (void *)EFI_SECURITY_VIOLATION;

  EFI_VARIABLE_AUTHENTICATION_2 *auth = param_3;

  *timestamp = auth->TimeStamp;

  if ( timestamp->Nanosecond != 0 ||
       timestamp->TimeZone != 0 ||
       timestamp->Daylight != 0 ||
       timestamp->Pad2 != 0 ||
       timestamp->Pad1 != 0 )
  {
    return EFI_SECURITY_VIOLATION;
  }

  if (((AUTH_ENFORCE && (param_9 != 4)) && (param_7 != '\x01')) &&
     ((param_8 != 0 && FUN_00403720(param_8 + 0x34) == '\0')))
  {
    return EFI_SECURITY_VIOLATION;
  }

#if 0
  if ( param_3->field_0x16 != WIN_CERT_TYPE_EFI_GUID)
  {
    return EFI_SECURITY_VIOLATION;
  }
#endif

  if ( auth->AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID )
    return EFI_SECURITY_VIOLATION;

#if 0
  if ( memcmp((void *)&param_3->field_0x18, &DAT_0040a240, 0x10) != 0 )
  {
    return EFI_SECURITY_VIOLATION;
  }
#endif

  if ( memcmp(&auth->AuthInfo.CertType, &gEfiCertPkcs7Guid, sizeof(EFI_GUID)) != 0 )
    return EFI_SECURITY_VIOLATION;

  /* Length of the entire certificate, including header */
  header_size = sizeof(auth->AuthInfo.Hdr);

  /* Size of certificate, not including the header */
  cert_size = auth->AuthInfo.Hdr.dwLength - header_size - sizeof(auth->AuthInfo.CertType);

  // Test that new equals old code:  cert_size = dwLength - 0x18;
  assert((sizeof(auth->AuthInfo.Hdr) + sizeof(auth->AuthInfo.CertType)) == 0x18);

  if ( total_size_param - 0x28 < cert_size )
  {
    return EFI_SECURITY_VIOLATION;
  }

  //  body = (undefined *)((long)&param_3->field_0x10 + header_size);
  body = (void*)(((uint64_t)&auth->AuthInfo) + header_size);
  body_size = (total_size_param - header_size) - 0x10;

  if ( param_9 == 4 )
  {
    dest = (astruct_2 *)malloc(cert_size);

    if ( !dest )
      return (void *)EFI_DEVICE_ERROR;

  //  memcpy(dest, &param_3->field_0x28, cert_size);
    memcpy(dest, &auth->AuthInfo.CertData[0], cert_size);
  }
  else
  {
    status = (void *)EFI_SECURITY_VIOLATION;

    if ( cert_size < 0x11 )
    {
      status = (void *)EFI_SECURITY_VIOLATION;
      goto end;
    }


    uint8_t *p = (uint8_t*)&auth->AuthInfo.CertData[0];

    // p     :  Tag (Sequence == 0x30)
    // p + 1 :  Length
    // p + 2 :  Tag (Integer == 0x02)
    // p + 3 :  Length
    // p + 4 :  Tag

    /* Skip passed ASN.1 Sequence tag and length */
    //p = p + 2;

    /* Skip passed ASN.1 Integer type and length for Version  */
    //p = p + 2;


    bool wrapped = false;

    // If this is an object of length 9, and it equals the object at DAT_0040a9c0
    if ( p[4] == 0x6 &&
         p[5] == 0x9 &&
         memcmp(&p[6], &mOidValue, sizeof(mOidValue)) == 0  &&
         p[15] == 0xa0 &&
         p[16] == 0x82 )
    {
        wrapped = true;
    }

    if ( wrapped )
    {
      dest = malloc(cert_size);
      if ( !dest )
      {
        status = (void *)EFI_DEVICE_ERROR;
        goto end;
      }

      memcpy(dest, &p, cert_size);
    }
    else
    {
      src_sz = header_size - 5;
      dest = (astruct_2 *)malloc(src_sz);
      if ( !dest )
      {
        status = (void *)EFI_DEVICE_ERROR;
        goto end;
      }

      /* Build another DER-encoded cert */
      dest->field_0x0 = 0x30;
      dest->field_0x1 = 0x82;
      dest->field_0x2 = (char)(((short)src_sz - 4) >> 8);
      dest->field_0x3 = (char)src_sz + -4;
      dest->field_0x4 = 6;
      dest->field_0x5 = 9;
      dest->field_0x6 = 0x7010df78648862a;
      dest->field_0xe = 2;
      dest->field_0xf = 0xa0;
      dest->field_0x10 = 0x82;
      dest->field_0x12 = (char)cert_size;
      dest->field_0x11 = (char)(cert_size >> 8);

      memcpy(&dest->field_0x13, &param_3->field_0x28, cert_size);
    }

    if ((0x28 < src_sz) &&
       ((*(char *)&dest->field_0x14 != -0x7e ||
        (memcmp(dest + 1,&DAT_0040a960,9) != 0)))) {
      status = (void *)EFI_SECURITY_VIOLATION;
      src = (undefined8 *)0x0;
      __s1 = (void *)0x0;
      goto end;
    }
  }
  cert_size = (total_size_param - header_size) + 0x14 + param_2;
  src = malloc(cert_size);
  ptr = src;
  if ( !src )
  {
    return (void *)EFI_DEVICE_ERROR;
  }


  memcpy(ptr, param_1, param_2);
  ptr += param_2;

  memcpy(ptr, param_5, 2);
  ptr += 2;

  if ( param_7 != 0 )
  {
    param_6 = param_6 | 0x40;
  }

  memcpy(ptr, &param_6, sizeof(param_6));

  tmp_struct6 = (astruct_6*) (ptr + 0x14);
  tmp_struct6->field_0x0 = param_3->field_0x0;
  tmp_struct6->field_0x8 = param_3->field_0x8;
  memcpy(&tmp_struct6->field_0x10, body, body_size);

  if (param_9 == 0) {
    status = (void *)certificate_get_signers(dest, src_sz, &pkcs7, &signer_stack);
    __s1 = (void *)0x0;
    if ( status )
        goto end;
    status = (void *)EFI_SECURITY_VIOLATION;
    count = sk_num(signer_stack);
    if ( count == 0 )
        goto end;
    status = (void *)EFI_DEVICE_ERROR;
    count = sk_num(signer_stack);
    x509_cert = sk_value(signer_stack, count - 1);
    x509_der = encode_X509_der(x509_cert, &x509_len);
    __s1 = x509_der;
    if ( !x509_der )
        goto end;

    if ( get_variable_data(PK, 4, &variable_data, &pp) != 0 )
    {
        status = (void *)EFI_SECURITY_VIOLATION;
        goto end;
    }

    status = (void *)EFI_SECURITY_VIOLATION;


    EFI_SIGNATURE_LIST *list;

    list = variable_data;

    if ( x509_len != list->SignatureSize - sizeof(EFI_GUID) )
    {
        status = (void *)EFI_SECURITY_VIOLATION;
        goto end;
    }
    
    if (memcmp((void *)((long)variable_data + (unsigned long)(list->SignatureHeaderSize) + 0x2c)
                        x509_der, x509_len) != 0) ||
       (verify_authvar(dest, src_sz, x509_cert, src, cert_size) != 0))
        goto end;

// WIP
#if 0
    if (((x509_len != (ulong)*(uint *)((long)variable_data + 0x18) - 0x10) ||
        (memcmp((void *)((long)variable_data + (ulong)*(uint *)((long)variable_data + 0x14) + 0x2c)
                        x509_der, x509_len) != 0)) ||
       (verify_authvar(dest, src_sz, x509_cert, src, cert_size) != 0))
        goto end;
#endif
    *out_sz = body_size;
    *out_ptr = (undefined *)malloc(body_size);
    if ( *out_ptr )
    {
          memcpy(*out_ptr, body, body_size);
          goto end;
    }

    status = (void *)EFI_DEVICE_ERROR;
    __s1 = x509_der;
    goto end;
  }

  if (param_9 == 1)
  {
    if ( get_variable_data(KEK, 6, &variable_data) == 0 )
    {
      __s1 = variable_data;
      while (0 < (int)(uint)pp)
      {
        if ( memcmp(__s1, &DAT_0040a250, 0x10) == 0 )
        {
          uVar1 = *(uint *)((long)__s1 + 0x10);
          uVar2 = *(uint *)((long)__s1 + 0x14);
          uVar3 = *(uint *)((long)__s1 + 0x18);
          lVar7 = (long)__s1 + (ulong)uVar2 + 0x1c;
          iVar6 = 0;
          while (iVar6 < SUB164(ZEXT816((uVar1 - 0x1c) - uVar2) / ZEXT416(uVar3), 0))
          {
            x509_cert_buf = (uchar *)(lVar7 + 0x10);
//            local_b8[0] = (uchar *)(lVar7 + 0x10);
            a = d2i_X509(NULL, &x509_cert_buf, *(uint *)((long)__s1 + 0x18) - 0x10);
            if ( a != NULL )
            {
              status = (void *)verify_authvar(dest, src_sz, a, src, cert_size);
              X509_free(a);
              if ( !status )
              {
                *out_sz = body_size;
                *out_ptr = malloc(body_size);
                if ( *out_ptr )
                {
                  memcpy(*out_ptr, body, body_size);
                  goto end;
                }
                status = (void *)EFI_DEVICE_ERROR;
                goto end;
              }
            }
            iVar6 = iVar6 + 1;
            lVar7 = lVar7 + (ulong)*(uint *)((long)__s1 + 0x18);
          }
        }
        pp._0_4_ = (uint)pp - *(uint *)((long)__s1 + 0x10);
        __s1 = (void *)((long)__s1 + (ulong)*(uint *)((long)__s1 + 0x10));
      }
      status = (void *)EFI_SECURITY_VIOLATION;
      __s1 = (void *)0x0;
      goto end;
    }
    status = (void *)EFI_SECURITY_VIOLATION;
    goto end;
  }
  else
  {
    if ( param_9 == 2 )
    {
      if ( body_size == 0 )
        goto end;

      if ( body_size >= 0x1b )
      {
          status = (void *)EFI_SECURITY_VIOLATION;
          goto end;
      }

      uVar1 = *(uint *)(body + 0x18);
      if (((ulong)*(uint *)(body + 0x14) + 0x1c + (ulong)uVar1 <= body_size) && (0xf < uVar1))
      {
        x509_cert_buf = body + (ulong)*(uint *)(body + 0x14) + 0x2c; 
//        local_b8[0] = body + (ulong)*(uint *)(body + 0x14) + 0x2c;
        a = d2i_X509((X509 **)0x0, &x509_cert_buf, (ulong)uVar1 - 0x10);
        if (a != (X509 *)0x0)
        {
          status = (void *)verify_authvar(dest, src_sz, a, src, cert_size);
          X509_free(a);
          __s1 = (void *)0x0;
          if ( status )
            goto end;
          *out_sz = body_size;
          *out_ptr = (undefined *)malloc(body_size);
          __s1 = (void *)0x0;
          if ( *out_ptr == NULL )
          {
            status = (void *)EFI_DEVICE_ERROR;
            goto end;
          }

          memcpy(*out_ptr, body, body_size);
          goto end;
        }
      }
    }
    if ( param_9 != 3 )
    {
      __s1 = (void *)0x0;
      status = (void *)EFI_DEVICE_ERROR;
      if ( param_9 == 4 )
      {
        *out_sz = body_size;
        *out_ptr = malloc(body_size);
        if ( *out_ptr ) {
          status = (void *)0x0;
          memcpy(*out_ptr, body, body_size);
        }
      }
      goto end;
    }

    status = (void *)certificate_get_signers(dest, src_sz, &pkcs7, &signer_stack);

    __s1 = (void *)0x0;

    if ( status )
        goto end;

    iVar6 = sk_num(signer_stack);
    if ( iVar6 == 0 ) {
      status = (void *)EFI_SECURITY_VIOLATION;
      goto end;
    }

    iVar6 = sk_num(signer_stack);
    __s1 = sk_value(signer_stack, iVar6 - 1);
    a = (X509 *)sk_value(signer_stack, 0);
    name = X509_get_subject_name(a);

    if ( !name )
    {
      status = (void *)EFI_SECURITY_VIOLATION;
      goto end;
    }

    int nid = 0xd;
    if ( X509_NAME_get_text_by_NID(name, NID_commonName, (char *)x509_cert_buf, 0x80) < 0 )
    {
      status = (void *)EFI_SECURITY_VIOLATION;
      goto end;
    }

    void *der_ptr;
    der_ptr = encode_X509_der(__s1, &omax);

    if ( !der_ptr )
      status = (void *)EFI_DEVICE_ERROR;
      goto end;

    plength = 0;
    pp = der_ptr;
    ASN1_get_object(&pp, &plength, &ptag, &pclass, omax);
  
    if ( ptag != V_ASN1_SEQUENCE )
    {
      ASN1_get_object(&pp, &plength, &ptag, &pclass, plength)
  
      if ( ptag != V_ASN1_SEQUENCE )
      {
          free(der_ptr);
          status = (void *)EFI_SECURITY_VIOLATION;
          goto end;
      }
    }
  
    data = malloc((size_t)plength);
    if ( !data )
    {
      status = (void *)EFI_DEVICE_ERROR;
      free(der_ptr);
      goto end;
    }
  
    memcpy(data, pp, plength);
  
    free(der_ptr);
    status = do_sha_hash(sha256_cipher, data, x509_cert_buf, plength);
    free(data);
    if ( status )
      goto end;
  
    free(data);
    if ( !status )
    {
      if (((AUTH_ENFORCE == true) || (param_8 == 0)) ||
         (memcmp(sha256_cipher, (void *)(param_8 + 0x44), 0x20) == 0))
      {
        __s2 = NULL;
        status = (void *)verify_authvar(dest, src_sz, __s1, src, cert_size);
        if ( status )
          goto end;
        *out_sz = body_size;
        *out_ptr = malloc(body_size);
        if ( *out_ptr != NULL )
        {
          memcpy(*out_ptr, body, body_size);
          goto end;
        }
        status = (void *)EFI_DEVICE_ERROR;
        __s1 = x509_der;
        goto end;
      }

      status = EFI_SECURITY_VIOLATION;
      goto end;
    }
  }
  
end:
  if ( dest )
      free(dest);
  if ( variable_data )
      free(variable_data);
  if ( __s1 )
      free(__s1);
  if ( src )
      free(src);
  if ( signer_stack )
      sk_free(signer_stack);
  if ( pkcs7 )
      PKCS7_free(pkcs7);
  return status;
}
