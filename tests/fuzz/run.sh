#!/bin/bash

set -x

FUZZ_BIN=$1
CORPUS=${FUZZ_BIN}.corpus

${FUZZ_BIN} ${CORPUS} 
