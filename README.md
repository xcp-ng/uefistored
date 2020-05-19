# VM Secure Boot

This project aims to support UEFI Secure Boot in guest VMs on XCP-ng.

## Overview

varstored-ng is a service that runs in dom0 userspace for servicing port IO RPC
requests from the OVMF XenVariable module, thus providing a protected UEFI
Variables Service implementation.

varstored-ng (the executable is simply `varstored`) is started by the XAPI
stack upon running a VM.  One running varstored-ng process exists per HVM
domain start via XAPI.

varstored-ng uses Xen's libxen to register itself as a device emulator for the
HVM domU that XAPI has started.  XenVariable, found in OVMF, knows how to
communicate with varstored-ng using the device emulation protocol.  See [OVMF
and varstored-ng] for more details.

## OVMF and varstored-ng

OVMF's XenVariable module implements the UEFI Variables service (see the UEFI
v2 spec).  When a call is made to the UEFI Variables service, XenVariable
passes the call to varstored-ng via a mechanism of port IO and shared memory.

For example, when OVMF makes a GetVariable call, XenVariable packages a call ID
indicating "GetVariable" and the arguments of the call onto a memory page that
is shared with varstored-ng [1].  It writes the address of that shared memory
to port 0x100, which Xen routes to varstored-ng.  varstored-ng then grabs the
memory location, maps it in, and handles the request resident in it.  Once it
has been handled and the response has been loaded into the shared memory, an
event channel notification is used to indicate to the guest that its
GetVariable request has been served and the response is ready for processing.

[1] varstored-ng uses the `xenforeignmemory_map()` API to map in the
    OVFM memory page that XenVariable uses.  XenVariable communicates
    the location of this page to varstored-ng using port IO caught by
    a IOREQ server initialized by varstored-ng.
