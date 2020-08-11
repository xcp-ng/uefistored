#!/bin/bash

set -x

FUZZ_BIN=$1
shift

CORPUS=${FUZZ_BIN}.corpus
RUNS=50000

for len in 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768; do
    ${FUZZ_BIN} ${CORPUS} -print_coverage=1 -max_len=${len} -runs=${RUNS}
done
