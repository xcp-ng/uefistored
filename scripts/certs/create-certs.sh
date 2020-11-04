#!/bin/bash

# This script generates a set of PK variables that can be used to test PK functionality.
# The output certs are numbered in the order in which they should be set to test
# various PK variable functionalities.  They should be set using the command:
#
# $ efi-updatevar -f <auth_file> PK

set -e

GUID="e8e1f046-04f5-4e5c-ba83-5a78e828cd2d"

create_x509() {
    local var=$1

    openssl req \
        -newkey rsa:4096 -nodes -keyout ${var}.key \
        -new -x509 -sha256 -days 3650   \
        -subj "/CN=${var} Owner/" -out ${var}.crt

    openssl x509 -outform DER -in ${var}.crt -out ${var}.der
}

create_esl() {
    local var=$1

    cert-to-efi-sig-list -g "${GUID}" ${var}.crt ${var}.esl
}

sign() {
    local signer=$1
    local var=$2
    local auth=$3

    if [[ "$@" =~ "--null" ]];
    then
        esl=null.esl
    else
        esl=${var}.esl
    fi

    # Wait a second to ensure a new timestamp
    sleep 1

    sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %T')" -g "${GUID}" \
                      -k ${signer}.key -c ${signer}.crt ${var} ${esl} ${auth}
}

set -x

> null.esl

create_x509 PK
create_x509 KEK
create_x509 DB
create_x509 newPK

create_esl PK
create_esl KEK
create_esl DB

sleep 1
sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')" -g "${GUID}" \
                  -k PK.key -c PK.crt db DB.esl DB-signed-by-PK.auth

sleep 1
sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')"  -g "${GUID}" \
                  -k KEK.key -c KEK.crt db DB.esl DB-signed-by-KEK.auth

sign PK PK PK.auth
sign PK KEK KEK.auth

sign PK PK nullPK.auth --null
sign PK KEK nullKEK.auth --null
sign KEK DB nullDB-signed-by-KEK.auth --null
sign PK DB nullDB-signed-by-PK.auth --null

sleep 1

# A new and good PK
create_esl newPK
sign-efi-sig-list -t "$(date --date='1 second' +'%Y-%m-%d %T')" -g "${GUID}" \
                  -k PK.key -c PK.crt PK newPK.esl newPK.auth

# Bad PK
create_x509 PK
create_esl badPK
sign PK badPK badPK.auth

mkdir -p test-certs/
mv *.der *.esl *.key *.crt *.auth test-certs/
