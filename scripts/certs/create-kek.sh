#!/bin/bash

set -e

usage="$0 <pk-key> <pk-crt>"

die() {
    echo "$@" >&2
    exit 1
}

if [[ $# != 2 ]];
then
    die "${usage}"
fi

pk_key=$1
pk_crt=$2

# temporary Vates SAS guid: 0xe8, 0xe1, 0xf0, 0x46, 0x04, 0xf5, 0x4e, 0x5c, 0xba, 0x83, 0x5a, 0x78, 0xe8, 0x28, 0xcd
GUID="e8e1f046-04f5-4e5c-ba83-5a78e828cd2d"

openssl req \
    -newkey rsa:4096 \
    -nodes -keyout KEK.key \
    -new -x509 -sha256 \
    -days 3650 \
    -subj "/CN=Oscar/" \
    -out KEK.crt

openssl x509 -outform DER -in KEK.crt -out KEK.der
cert-to-efi-sig-list -g "${GUID}" KEK.crt KEK.esl
sign-efi-sig-list \
    -t "$(date +'%Y-%m-%d %T')" \
    -g "${GUID}" \
    -k ${pk_key} \
    -c ${pk_crt} KEK KEK.esl KEK.auth


echo "KEK saved to KEK.auth"
