#!/bin/bash

set -e
set -x

if [[ "x${PORT}" == "x" ]]; then
    PORT=22
fi

UEFISTORE=/usr/sbin/uefistored
VARSTORE=$(ssh -p${PORT} root@${XCP_NG_IP} which varstored)

scp -P${PORT} uefistored root@${XCP_NG_IP}:${UEFISTORE}
ssh -p${PORT} root@${XCP_NG_IP} ln -sf ${UEFISTORE} ${VARSTORE}
