#!/bin/python

import time
import subprocess
import os
import sys

varstored = "/root/varstored"


for i,arg in enumerate(sys.argv):
    if arg == '--pidfile':
        break
i += 1

pidfile = sys.argv[i]
with open(pidfile, 'w') as f:
    f.write(str(os.getpid()))

newpidfile = "/root/tmp.pid"
sys.argv[i] = newpidfile

time.sleep(2)
os.execv(varstored, sys.argv)
