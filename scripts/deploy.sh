#!/bin/bash

varstore_path=$(ssh root@${XCP_NG_IP} which varstored)
scp varstored root@${XCP_NG_IP}:${varstore_path}
