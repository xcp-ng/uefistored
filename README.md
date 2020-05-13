# VM Secure Boot

This project aims to support UEFI Secure Boot in guest VMs on XCP-ng.

## Message Specification

#### Header

```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Version  (u32)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Command  (u32)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Set Variable

Variable Name Length : u64 (8 bytes)
Variable Name        : size equal to the value of "Variable Name Length" Field
GUID                 : 16 bytes
Data Length          : u64 (8 bytes)
Data:                : size equal to the value of "Data Length" field

###



## TODO

- [x] Build OVMF from https://github.com/xcp-ng-rpms/edk2.git
- [x] Create a VM that uses this OVMF (hvmloader)
- [x] Setup virtual network with QEMU dev machine
- [x] Install XCP-ng on QEMU dev machine
- [x] Deploy well-known image with XL
- [x] Deploy on XCP-ng native host to simplify virtual net
- [x] Deploy on XCP-ng native host with OVMF
- [x] Test varstored on xcp-ng with the new VM to see the behavior
- [x] Create new varstored prototype program that registers an IOREQ server (port
      address 0x100 to 0x103)
- [x] Prints out received IO requests
- [x] Map in IO page (commands from UEFI)
- [x] Return GetVariable() requests from memory   
- [x] Save SetVariable() requests in memory   
- [x] Return GetVariable() requests from simple file-backed db   
- [x] Save SetVariable() requests  to simple file-backed db  
- [ ] Start with builtin vars
- [ ] GetNextVariableName() 
- [ ] Instead of simple file-backed db, implement using XAPI DB backend.
- [ ] Implement varstore-get/set/ls and varstore-sb-state
- [ ] Generate keys and binaries with efitools for guest
- [ ] Load keys and binaries from efitools into guest OVMF
