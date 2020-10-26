#!/bin/bash

set -e

usage="$(basename $0) <privkey> <pubkey-cert> <new-cert|null> <output-new-auth>"

GUID="e8e1f046-04f5-4e5c-ba83-5a78e828cd2d"

die() {
    echo "$@" >&2
    exit 1
}

if [[ "$@" =~ "help" ]];
then
    die "${usage}"
fi

if [[ "x$1" = "x" || "x$2" = "x" || "x$3" = "x" || "x$4" = "x" ]];
then
    die "${usage}"
fi

priv=$1
cert=$2
new_cert=$3
new_auth=$4

if [[ "x$new_cert" = "xnull" ]];
then
    esl=$(dirname ${new_auth})/null.esl
    > ${esl}
else
    esl=${new_cert/.*/.esl}
    cert-to-efi-sig-list -g "${GUID}" ${new_cert} ${esl}
fi

sign-efi-sig-list \
    -t "$(date +'%Y-%m-%d %T')" \
    -g "${GUID}" \
    -k ${priv} \
    -c ${cert} PK ${esl} ${new_auth}

# Create a C array of the auth
# printf "%s, %s, %s, %s, %s, %s, %s, %s,\n" $(hexdump -v -e '/1 " 0x%02x"' PK.auth) | sed 's/, ,//g' | sed '$s/,$//g' > PK.array
