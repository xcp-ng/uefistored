#!/bin/bash

# Vates SAS guid: 0xe8, 0xe1, 0xf0, 0x46, 0x04, 0xf5, 0x4e, 0x5c, 0xba, 0x83, 0x5a, 0x78, 0xe8, 0x28, 0xcd

GUID="e8e1f046-04f5-4e5c-ba83-5a78e828cd2d"

openssl req \
    -newkey rsa:4096 \
    -nodes -keyout PK.key \
    -new -x509 -sha256 \
    -days 3650 \
    -subj "/CN=Vates SAS/" \
    -out PK.crt

openssl x509 -outform DER -in PK.crt -out PK.cer
cert-to-efi-sig-list -g "${GUID}" PK.crt PK.esl
sign-efi-sig-list -g "${GUID}" -k PK.key -c PK.crt PK PK.esl PK.auth
