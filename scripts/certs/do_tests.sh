#!/bin/bash

GUEST=$1

EFI_GLOBAL_GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c

die() {
    echo "$@" >&2
    exit 1
}

do_ssh() {
    ssh root@${GUEST} -- $@ >/dev/null
    return $?
}

efi_set() {
    local variable=$1
    local auth_file=$2

    do_ssh chattr -i /sys/firmware/efi/efivars/${variable}-*
    do_ssh mkdir -p $(dirname ${auth_file})
    scp ${auth_file} root@${GUEST}:${auth_file}
    do_ssh efi-updatevar -f ${auth_file} ${variable}
    return $?
}

show_result() {
    local variable=$1
    local expected=$2
    local auth_file=$3
    local result=$4

    if [[ "x${result}" != "x0" && "x${expected}" = "xsuccess"  ]];
    then
        die "Failed setting PK ${auth_file}, expected success"
    fi

    if [[ "x${result}" == "x0" && "x${expected}" != "xsuccess" ]]
    then
        die "Test failure, setting PK ${auth_file} succeed, expected failure"
    fi

    echo "Test of ${auth_file} passed!"
}

test_set_pk() {
    local auth_file=$1
    local expected=$2

    efi_set PK ${auth_file}
    show_result PK ${expected} ${auth_file} $?
}

test_set_kek() {
    local auth_file=$1
    local expected=$2

    efi_set KEK ${auth_file}
    show_result KEK ${expected} ${auth_file} $?
}

setup() {
    do_ssh stat /sys/firmware/efi/efivars/KEK-$EFI_GLOBAL_GUID

    if [[ "$?" = "0" ]];
    then
        die "KEK already exists, tests must start on a system with no KEK!"
    fi
}

setup

test_set_pk test-certs/2-null.auth success
test_set_pk test-certs/3-PK.auth success
test_set_pk test-certs/4-new_PK.auth success
test_set_pk test-certs/5-PK.auth failure
test_set_pk test-certs/6-null.auth failure
test_set_pk test-certs/7-invalid_PK.auth failure
test_set_pk test-certs/8-newest-new_PK.auth success
test_set_pk test-certs/9-oldest-new_PK.auth failure

test_set_kek test-certs/signed-by-new-PK/KEK.auth success
test_set_kek test-certs/signed-by-new-PK/null.auth success
test_set_kek test-certs/signed-by-original-PK/KEK.auth failure
test_set_kek test-certs/signed-by-new-PK/KEK.auth success

echo "All tests passed!"
