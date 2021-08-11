#!/bin/bash

# This script generates a set of auth variables that can be used to test secure boot.

set -e

GLOBAL_GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"
DB_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
seconds=0

create_x509() {
    local var=$1

    openssl req \
        -newkey rsa:4096 -nodes -keyout ${var}.key \
        -new -x509 -sha256 -days 3650   \
        -subj "/CN=Test Owner/" -out ${var}.crt

    openssl x509 -outform DER -in ${var}.crt -out ${var}.der
}

new_time() {
    date --date="${1} second" +'%Y-%m-%d %T'
}

> null.esl

create_x509 PK
create_x509 newPK
create_x509 badPK
create_x509 KEK
create_x509 db
create_x509 db-append
create_x509 db2

cert-to-efi-sig-list -g "${GLOBAL_GUID}" PK.crt PK.esl
cert-to-efi-sig-list -g "${GLOBAL_GUID}" KEK.crt KEK.esl
cert-to-efi-sig-list -g "${DB_GUID}" db.crt db.esl
cert-to-efi-sig-list -g "${DB_GUID}" db-append.crt db-append.esl
cert-to-efi-sig-list -g "${DB_GUID}" db2.crt db2.esl
cert-to-efi-sig-list -g "${DB_GUID}" newPK.crt newPK.esl
cert-to-efi-sig-list -g "${DB_GUID}" badPK.crt badPK.esl

set -x

# dbs
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})" -g "${DB_GUID}" \
                  -k KEK.key -c KEK.crt db db.esl db.auth
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})" -g "${DB_GUID}" \
                  -k PK.key -c PK.crt db db.esl db-signed-by-PK.auth
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})"  -g "${DB_GUID}" \
                  -k KEK.key -c KEK.crt db db.esl db-signed-by-KEK.auth

# db with append attribute
let "seconds=seconds+1"
sign-efi-sig-list -a -t "$(new_time ${seconds})" -g "${DB_GUID}" \
                  -k KEK.key -c KEK.crt db db-append.esl db-append.auth

# PKs
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})"  -g "${GLOBAL_GUID}" \
                  -k PK.key -c PK.crt PK PK.esl PK.auth
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})" -g "${GLOBAL_GUID}" \
                  -k PK.key -c PK.crt PK newPK.esl newPK.auth
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})" -g "${GLOBAL_GUID}" \
                  -k PK.key -c PK.crt PK null.esl nullPK.auth
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})" -g "${GLOBAL_GUID}" \
                  -k badPK.key -c badPK.crt PK badPK.esl badPK.auth

# KEKs
let "seconds=seconds+1"
sign-efi-sig-list -t "$(new_time ${seconds})" -g "${GLOBAL_GUID}" \
                  -k PK.key -c PK.crt KEK KEK.esl KEK.auth

set +x

mkdir -p test-certs/
yes | rm test-certs/*
mv *.der *.esl *.key *.crt *.auth test-certs/
