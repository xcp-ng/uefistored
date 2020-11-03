#!/bin/bash

set -e

usage="$0 <pk-key> <pk-crt> [--null]"

die() {
    echo "$@" >&2
    exit 1
}


pk_key=$1
pk_crt=$2

if [[ "x$pk_key" = "x" || "x$pk_crt" = "x" ]];
then
    die "${usage}"
fi

if [[ "$@" =~ "--null" ]];
then
    is_null=1
else
    is_null=0
fi

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

if [[ "${is_null}" = "1" ]];
then
    esl=null.esl
    auth=null.auth
    > ${esl}
else
    esl=KEK.esl
    auth=KEK.auth
    cert-to-efi-sig-list -g "${GUID}" KEK.crt ${esl}
fi

sign-efi-sig-list \
    -t "$(date +'%Y-%m-%d %T')" \
    -g "${GUID}" \
    -k ${pk_key} \
    -c ${pk_crt} KEK ${esl} ${auth}

echo "KEK saved to ${auth}"
