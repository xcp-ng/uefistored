# VM Secure Boot

This document describes a system for supporting UEFI Secure Boot in HVM guest
virtual machines (VMs).


## Motivation for VM Secure Boot

To protect users by preventing the execution of compromised guest operating
systems.


## Goals

- Guarantee guest operating system integrity
- Maintain security properties equal to those of real world systems (i.e., VM
  UEFI Secure Boot should offer similar security guarantees as UEFI Secure Boot
  on a hardware platform)
- Minimize or avoid adding unnecessary complexity to the highest privileged
  component (i.e., the hypervisor).
- Support the maintainance and development of the project via open licensing


## Context

UEFI is a firmware specification that describes how operating systems should
interact with the firmware as well as how the operating system should be
booted.

UEFI Secure Boot is part of the UEFI specification.  The purpose of UEFI Secure
Boot is ensure the integrity of the operating system at boot
time.  UEFI Secure Boot achieves this by performing cryptographic integrity
verification of the operating system prior to its execution.  If the operating
system fails this verification, it is not loaded and it is not executed.

The UEFI Secure Boot integrity verification mechanism depends on the use of
cryptographic keys which are stored as UEFI variables.  UEFI variables are
accessed and manipulated by the UEFI Variable service, which defines the
GetVariable and SetVariable methods.   Because of the sensitivity of these
keys, their storage, and management, these UEFI Variable methods are protected
by being accessible only in SMM mode and the variables are stored in SMRAM.


## Architecture

Virtualizing UEFI Secure Boot should preserve the properties observed in the
above-mentioned architecture.  These include, (1) operating system integrity is
verified prior to execution, and (2) UEFI Variables and Variable service
methods reside in a protected space.

### OVMF

TODO: Describe the OVMF patchset

### Port IO RPC

TODO: Describe the Port IO RPC mechanism

###  Port IO RPC Server

TODO: Describe the Port IO RPC Server

#### RPC Message Format

TODO

### Server Key Management

TODO: Describe how the server will manage keys securely

#### UEFI Key Management

TODO

#### KEK

TODO

#### PK

TODO

#### db / dbx

TODO

## Future Improvements

TODO: Describe improvements (see VM Secure Boot trello ticket)
