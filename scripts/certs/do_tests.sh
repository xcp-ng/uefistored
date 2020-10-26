#!/bin/bash

GUEST=$1

setup_file() {
    scp ${file} root@$GUEST:/home/test/
}

do_ssh() {
    ssh root@${GUEST} -- $@ >/dev/null
    return $?
}

test_setting_pk() {
    auth_file=$1
    expected=$2

    do_ssh chattr -i /sys/firmware/efi/efivars/PK-*
    scp ${auth_file} root@${GUEST}:${auth_file}
    do_ssh efi-updatevar -f ${auth_file} PK

    ret=$?
    if [[ "x$ret" != "x0" && "x$expected" = "xsuccess"  ]];
    then
        die "Failed setting PK ${auth_file}, expected success"
    fi

    if [[ "x$ret" == "x0" && "x$expected" != "xsuccess" ]]
    then
        die "Test failure, setting PK ${auth_file} succeed, expected failure"
    fi

    echo "Test of ${auth_file} passed!"
}


test_setting_pk test-certs/1-PK.auth success
test_setting_pk test-certs/2-null.auth success
test_setting_pk test-certs/3-PK.auth success
test_setting_pk test-certs/4-new_PK.auth success
test_setting_pk test-certs/5-PK.auth failure
test_setting_pk test-certs/6-null.auth failure
test_setting_pk test-certs/7-invalid_PK.auth failure
test_setting_pk test-certs/8-newest-new_PK.auth success
test_setting_pk test-certs/9-oldest-new_PK.auth failure
