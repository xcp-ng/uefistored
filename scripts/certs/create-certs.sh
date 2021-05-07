#!/bin/bash

# This script generates a set of auth variables that can be used to test secure boot.
# They should be set using the command:
#
# $ efi-updatevar -f <auth_file> PK

set -e

GUID="e8e1f046-04f5-4e5c-ba83-5a78e828cd2d"

owner=$RANDOM

create_x509() {
    local var=$1

    openssl req \
        -newkey rsa:4096 -nodes -keyout ${var}.key \
        -new -x509 -sha256 -days 3650   \
        -subj "/CN=${owner} Owner/" -out ${var}.crt

    openssl x509 -outform DER -in ${var}.crt -out ${var}.der
}

create_esl() {
    local crt=$1
    local esl=$2

    cert-to-efi-sig-list -g "${GUID}" ${crt} ${esl}
}

sign() {
    local signer=$1
    local var=$2
    local esl=$3
    local auth=$4

    # Wait a second to ensure a new timestamp
    sleep 1

    sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %T')" -g "${GUID}" \
                      -k ${signer}.key -c ${signer}.crt ${var} ${esl} ${auth}
}

set -x

> null.esl

create_x509 KEK
create_x509 newPK

create_x509 PK
create_esl PK.crt PK.esl
create_esl KEK.crt KEK.esl

create_x509 db
create_esl db.crt db.esl

create_x509 db2
create_esl db2.crt db2.esl

sleep 1
sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')" -g "${GUID}" \
                  -k PK.key -c PK.crt db db.esl db-signed-by-PK.auth

sleep 1
sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')"  -g "${GUID}" \
                  -k KEK.key -c KEK.crt db db.esl db-signed-by-KEK.auth

sign PK PK PK.esl PK.auth
sign PK KEK KEK.esl KEK.auth

sign PK PK null.esl nullPK.auth
sign PK KEK null.esl nullKEK.auth
sign KEK db null.esl null-db-signed-by-KEK.auth
sign PK db null.esl null-db-signed-by-PK.auth

sign KEK db db.esl db.auth

sleep 2

sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %T')" -g "${GUID}" \
                  -k KEK.key -c KEK.crt db db2.esl db2.auth

sleep 1

# A new and good PK
create_esl newPK.crt newPK.esl
sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %T')" -g "${GUID}" \
                  -k PK.key -c PK.crt PK newPK.esl newPK.auth

# Bad PK
create_x509 badPK
create_esl badPK.crt badPK.esl
sign PK badPK badPK.esl badPK.auth

mkdir -p test-certs/
mv *.der *.esl *.key *.crt *.auth test-certs/
