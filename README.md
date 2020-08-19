# uefistored

This project aims to support UEFI Secure Boot in guest VMs on XCP-ng.

## Overview

uefistored is a service that runs in dom0 userspace for servicing port IO RPC
requests from the OVMF XenVariable module, thus providing a protected UEFI
Variables Service implementation.

uefistored (the executable is simply `uefistored`) is started by the XAPI
stack upon running a VM.  One running uefistored process exists per HVM
domain start via XAPI.

uefistored uses Xen's libxen to register itself as a device emulator for the
HVM domU that XAPI has started.  XenVariable, found in OVMF, knows how to
communicate with uefistored using the device emulation protocol.  See [OVMF
and uefistored] for more details.

## Executable

XAPI looks for an executable called varstored, so uefistored must be linked to
or renamed to varstored.  This is a requirement of XAPI.

## Deployment in Test

If you just want to deploy to a known host:

```
$ make all
$ XCP_NG_IP=192.168.0.17 make deploy
```

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
    OVFM memory page that XenVariable uses.  XenVariable communicates
    the location of this page to uefistored using port IO caught by
    a IOREQ server initialized by uefistored.

## UEFI Notes

### Authenticated Variables

NOT SUPPORTED YET.

When a variable is to be authenticated using `EFI_VARIABLE_AUTHENTICATION_2` it
must be packaged into an `EFI_VARIABLE_AUTHENTICATION_2` decriptor (define by
the `C` struct of the same name).  It's timestamp must be set and its CertType
must be set to `EFI_CERT_TYPE_PKCS7_GUID`.  The variable name, guid,
attributes, timestamp, and new value must be hashed with the SHA256 algorithm
and then the hash must be signed with an RSA 2048-bit key.  A DER-encoded
PKCS#7 v1.5 SignedData must be constructed according to UEFI 2.3.1 Errata C
section 7.2.1[1] which contains the signed hash and information the crypto
algorithms used.  It _will not_ contain the actual variable data.  This PKCS#7
v1.5 SignedData must be assigned to the `AuthInfo.CertData` member of the
`EFI_VARIABLE_AUTHENTICATION_2` descriptor.  Concatenate this discriptor with
the new variable data and pass it as the `Data` parameter to `SetVariable()`.


[1] https://uefi.org/sites/default/files/resources/UEFI_2_3_1_C.pdf



