#!/bin/bash

UEFISTORE=/usr/sbin/uefistored
VARSTORE=$(ssh root@${XCP_NG_IP} which varstored)

scp uefistored root@${XCP_NG_IP}:${UEFISTORE}
ssh root@${XCP_NG_IP} ln -sf ${UEFISTORE} ${VARSTORE}
