
ulong certificate_find(uint param_1,X509_STORE_CTX *param_2)

{
  X509 *pXVar1;
  int iVar2;
  int iVar3;
  X509_OBJECT *pXVar4;
  void *pvVar5;
  X509_OBJECT *x;
  int iVar6;
  
  iVar2 = X509_STORE_CTX_get_error(param_2);
  if ((iVar2 == 0x14) || (x = (X509_OBJECT *)0x0, iVar2 == 2)) {
    x = (X509_OBJECT *)malloc(0x10);
    if (x == (X509_OBJECT *)0x0) {
      return 0;
    }
    pXVar1 = param_2->current_cert;
    x->type = 1;
    *(X509 **)&x->data = pXVar1;
    CRYPTO_lock(9,0xb,"handler.c",0x1c7);
    pXVar4 = X509_OBJECT_retrieve_match(param_2->ctx->objs,x);
    if (pXVar4 == (X509_OBJECT *)0x0) {
      if ((iVar2 == 0x14) && (iVar3 = sk_num((_STACK *)param_2->chain), 0 < iVar3)) {
        iVar6 = 0;
        do {
          pvVar5 = sk_value((_STACK *)param_2->chain,iVar6);
          *(void **)&x->data = pvVar5;
          pXVar4 = X509_OBJECT_retrieve_match(param_2->ctx->objs,x);
          if (pXVar4 != (X509_OBJECT *)0x0) goto LAB_00406506;
          iVar6 = iVar6 + 1;
        } while (iVar6 != iVar3);
      }
    }
    else {
LAB_00406506:
      param_1 = 1;
    }
    CRYPTO_lock(10,0xb,"handler.c",0x1d8);
  }
  if ((iVar2 == 0x15) || (iVar2 == 0x1b)) {
    param_1 = 1;
  }
  else {
    if (iVar2 - 9U < 2) {
      param_1 = 1;
    }
  }
  free(x);
  return (ulong)param_1;
}

