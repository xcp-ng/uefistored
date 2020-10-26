#!/bin/bash

# This script generates a set of PK variables that can be used to test PK functionality.
# The output certs are numbered in the order in which they should be set to test
# various PK variable functionalities.  They should be set using the command:
#
# $ efi-updatevar -f <auth_file> PK

set -e

usage="$0 <root-crt> <root-key>"

die() {
    echo "$@" >&2
    exit 1
}

if [[ "x$1" = "x" || "x$2" = "x" ]];
then
    die "${usage}"
fi

root_crt=$1
root_key=$2

outdir=test-certs/
mkdir -p ${outdir}

GUID=$(cat ./GUID.txt)

# The PK X.509 Public Key Certificate
PK_crt=PK.crt

# The PK private key
PK_key=PK.key

# The EFI_VARIABLE_AUTHENTICATION_2 wrapper for efi-updatevar
PK_auth=PK.auth

# Sets PK to null, will revert system to SetupMode == 1
null_auth=null.auth

# Newer and valid PK, signed by the previous PK's private key
# See above PK_* definitions for meaning of types
new_PK_crt=new_PK.crt
new_PK_key=new_PK.key
new_PK_auth=new_PK.auth

# Invalid PKs, signed with the wrong private key
invalid_PK_crt=invalid_PK.crt
invalid_PK_key=invalid_PK.key
invalid_PK_auth=invalid_PK.auth

create_x509() {
    key=$1
    crt=$2
    
    openssl req \
        -newkey rsa:4096 \
        -nodes -keyout ${key} \
        -new -x509 -sha256 \
        -days 3650 \
        -subj "/CN=Joe Tester/O=Vates SAS/OU=XCP-ng Platform Team/" \
        -out ${crt}
}

cp ${root_crt} ${outdir}/${PK_crt}
cp ${root_key} ${outdir}/${PK_key}
create_x509 ${outdir}/${new_PK_key} ${outdir}/${new_PK_crt}
create_x509 ${outdir}/${invalid_PK_key} ${outdir}/${invalid_PK_crt}

# 1. Set the first PK (or just the same as root but newer timestamp), expected pass
./create-pk-auth.sh ${outdir}/${PK_key} ${outdir}/${PK_crt} ${outdir}/${PK_crt} ${outdir}/1-${PK_auth}

# Let timestamp advance 1 second
sleep 1

# 2. Delete the PK, expected pass
./create-pk-auth.sh ${outdir}/${PK_key} ${outdir}/${PK_crt} null ${outdir}/2-${null_auth}

# 3. Reset the first PK, expected pass
cp ${outdir}/1-${PK_auth} ${outdir}/3-${PK_auth}

sleep 1

# 4. Pass from first platform owner to another platform owner with new PK, expected pass
./create-pk-auth.sh ${outdir}/${PK_key} ${outdir}/${PK_crt} ${outdir}/${new_PK_crt} ${outdir}/4-${new_PK_auth}

# 5. Set old PK, expected fail
cp ${outdir}/1-${PK_auth} ${outdir}/5-${PK_auth}

# 6. Delete PK with old null auth, expected fail
cp ${outdir}/2-${null_auth} ${outdir}/6-${null_auth}

sleep 1

# 7.  Set with invalid signature, expected fail
./create-pk-auth.sh ${outdir}/${invalid_PK_key} ${outdir}/${invalid_PK_crt} ${outdir}/${invalid_PK_crt} ${outdir}/7-${invalid_PK_auth}

sleep 1

# 8-9. Set with correct sig but old timestamp, expected fail when setting auth 9
./create-pk-auth.sh  ${outdir}/${new_PK_key} ${outdir}/${new_PK_crt} ${outdir}/${new_PK_crt} ${outdir}/9-oldest-${new_PK_auth}

sleep 1

./create-pk-auth.sh ${outdir}/${new_PK_key} ${outdir}/${new_PK_crt} ${outdir}/${new_PK_crt} ${outdir}/8-newest-${new_PK_auth}


echo "Test script generated here: ${outdir}/test-generated-auths.sh"
ls ${outdir}/* | cpio -o > pk_test_certs.cpio
echo "Saved in archive pk_test_certs.cpio"
