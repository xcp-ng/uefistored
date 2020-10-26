#!/bin/bash

die() {
    echo "$@" >&2
    exit 1
}

usage="$0 <auth>"

if [[ "x$1" = "x" ]];
then
    die "${usage}"
fi

if [[ "$@" =~ "help" ]];
then
    die "${usage}"
fi


auth=$1
out=${auth/.*/.array}

printf "%s, %s, %s, %s, %s, %s, %s, %s,\n" $(hexdump -v -e '/1 " 0x%02x"' ${auth}) | sed 's/, ,//g' | sed '$s/,$//g' > ${out}

echo "Array saved to ${out}"
