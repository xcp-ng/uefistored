# uefistored

This project aims to support UEFI Secure Boot in guest VMs on XCP-ng.

## Overview

uefistored is a service that runs in dom0 userspace for servicing port IO RPC
requests from the OVMF XenVariable module, therefore providing a protected UEFI
Variables Service implementation.

## Building

To build uefistored:

```
make all
```

Use `make help` to see make targets:

```
$ make help

uefistored - UEFI Secure Boot Support for Xen Guest VMs

all:               Build uefistored (same as uefistored target)
uefistored:        Build uefistored
uefistored-debug:  Build uefistored with debug symbols
test:              Run uefistored unit tests with address sanitizers
install:           Install uefistored and secureboot-certs
deploy:            Deploy uefistored to a host
help:              Display this help
scan-build:        Use scan-build for static analysis
```

## Initializing keys for uefistored

Because Microsoft key's are not freely distributable, we must require users to
download the keys and use them themselves instead of packaging and distributing
the keys alongside uefistored.

This section shows you how to generate and install keys for uefistored, using
the Microsoft/UEFI keys necessary to support both Shim and Windows in secure
boot mode.

```
# Generate KEK
openssl req -newkey rsa:4096 -nodes -new -x509 -sha256 -days 3650 \
        -subj "/CN=KEK Owner/" \
        -keyout KEK.key \
        -out KEK.crt

# Self-sign KEK and creat KEK.auth
# NOTE: because this cert is self-signed it will not be provisionable from
# the guest, only as a file for uefistored to read from /var/lib/uefistored
/opt/xensource/libexec/create-auth -k KEK.key -c KEK.crt KEK KEK.auth KEK.crt

# Download Microsoft UEFI CA 2011
curl 'https://www.microsoft.com/pkiops/certs/MicCorUEFCA2011_2011-06-27.crt' --output MicCorUEFCA2011_2011-06-27.crt

# Download Microsoft UEFI PCA 2011
curl 'https://www.microsoft.com/pkiops/certs/MicWinProPCA2011_2011-10-19.crt' --output MicWinProPCA2011_2011-10-19.crt

# Note, if curling fails the original redirect links to the certs are here:
# * [MicWinProPCA2011_2011-10-19.crt](https://go.microsoft.com/fwlink/p/?linkid=321192)
# * [MicCorUEFCA2011_2011-06-27.crt](https://go.microsoft.com/fwlink/p/?linkid=321194)

# Sign Microsoft certs with your KEK and create a db.auth
/opt/xensource/libexec/create-auth -k KEK.key -c KEK.crt db db.auth MicWinProPCA2011_2011-10-19.crt MicCorUEFCA2011_2011-06-27.crt

cp *.auth /var/lib/uefistored/

# If you would like the most recent dbx, it may be found here:
# https://www.uefi.org/revocationlistfile

```

*NOTE*: If both curling and the redirect links fail, you may manually download the UEFI CA 2011 and
Production PCA 2011 from
[here](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance)

## Deployment during Test

If you just want to deploy to a known host:

```
$ make all
$ HOST=$HOSTNAME_OR_IP make deploy
```

## Backends

uefistored supports the implementation of alternative backends for the
persistent storage of variables.

Currently, the only implemented backend is for XAPI.

### The XAPI backend

uefistored uses Xen's libxen to register itself as a device emulator for the
HVM domU that XAPI has started.  XenVariable, found in OVMF, knows how to
communicate with uefistored using the device emulation protocol.  See [OVMF
and uefistored](#ovmf-and-uefistored) for more details.

## OVMF and uefistored

OVMF's XenVariable module implements the UEFI Variables service (see the UEFI
v2 spec).  When a call is made to the UEFI Variables service, XenVariable
passes the call to uefistored via a mechanism of port IO and shared memory.

For example, when OVMF makes a GetVariable call, XenVariable packages a call ID
indicating "GetVariable" and the arguments of the call onto a memory page that
is shared with uefistored [1].  It writes the address of that shared memory
to port 0x100, which Xen routes to uefistored.  uefistored then grabs the
memory location, maps it in, and handles the request resident in it.  Once it
has been handled and the response has been loaded into the shared memory, an
event channel notification is used to indicate to the guest that its
GetVariable request has been served and the response is ready for processing.

[1] uefistored uses the `xenforeignmemory_map()` API to map in the
    OVMF memory page that XenVariable uses.  XenVariable communicates
    the location of this page to uefistored using port IO caught by
    an IOREQ server initialized by uefistored.

# Contributing

Contributions are welcome and may be submitted as PRs to [github](https://github.com/xcp-ng/uefistored).

# Reporting bugs

Bugs may be reported as [github issues](https://github.com/xcp-ng/uefistored/issues).

Some helpful information may include:

* The output from `cat /var/log/daemon.log | grep uefistored` (if
  on XCP-ng) or from  uefistored stdout/stderr.
* Screenshots or text from the guest.

# Maintainers 

* Bob Eshleman bobby.eshleman@gmail.com

# Acknowledgements

The overall design of this solution and some of the code comes from the
[varstored](https://github.com/xapi-project/varstored).  Some of the code is
also derived from [edk2](https://github.com/tianocore/edk2).
