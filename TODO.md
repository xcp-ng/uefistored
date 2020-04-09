# TODO

1. Build OVMF from https://github.com/xcp-ng-rpms/edk2.git
2. Create a VM that uses this OVMF
3. Depoy this VM on xcp-ng
4. Test varstored on xcp-ng with the new VM to see the behavior
5. After seeing the correct behavior (i.e., signed os passes, unsigned fails),
   Uninstall varstored.

6. Create new varstored prototype program that registers an IOREQ server (port
   address 0x100 to 0x103)
	1. Prints out received IO requests
7. Save SetVariable() requests in memory   
8. Return GetVariable() requests from memory   
9. Instead of saving to memory, implement saving them in a XAPI DB backend.
10. Implement varstore-get/set/ls and varstore-sb-state
