# VM Secure Boot

This project aims to support UEFI Secure Boot in guest VMs on XCP-ng.

## TODO

- [ ] Build OVMF from https://github.com/xcp-ng-rpms/edk2.git
- [ ] Create a VM that uses this OVMF
- [ ] Depoy this VM on xcp-ng
- [ ] Test varstored on xcp-ng with the new VM to see the behavior
- [ ] After seeing the correct behavior (i.e., signed os passes, unsigned fails),
      then uninstall varstored.
- [ ] Create new varstored prototype program that registers an IOREQ server (port
      address 0x100 to 0x103)
- [ ] Prints out received IO requests
- [ ] Save SetVariable() requests in memory   
- [ ] Return GetVariable() requests from memory   
- [ ] Instead of saving to memory, implement saving them in a XAPI DB backend.
- [ ] Implement varstore-get/set/ls and varstore-sb-state
