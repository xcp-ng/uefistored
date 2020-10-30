#!/bin/bash

set -e
set -x

if [[ "x${PORT}" == "x" ]]; then
    PORT=22
fi

UEFISTORE=/usr/sbin/uefistored
scp -P${PORT} uefistored root@${HOST}:${UEFISTORE}
ssh -p${PORT} root@${HOST} -- ln -sf ${UEFISTORE} /usr/sbin/varstored
scp -P${PORT} scripts/certs/PK.auth root@${HOST}:/usr/share/varstored/PK.auth
