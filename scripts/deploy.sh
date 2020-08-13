#!/bin/bash

UEFI_BIN=/usr/sbin/uefistored

varstore_path=$(ssh root@${XCP_NG_IP} which varstored)
scp uefistored root@${XCP_NG_IP}:${UEFI_BIN}
ssh root@${XCP_NG_IP} ln -sf ${UEFI_BIN} ${varstore_path}
