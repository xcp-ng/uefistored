#!/usr/bin/env python3

VAR_FILE = 'new_variable.dat'

class Attrs:
    NON_VOLATILE = 0x1
    BOOTSERVICE_ACCESS = 0x2
    RUNTIME_ACCESS = 0x4

    @staticmethod
    def as_bytes(attrs):
        if attrs < 0xff:
            return bytearray([attrs, 0x0, 0x0, 0x0])
        else:
            raise RuntimeError('attributes > 0xff not implemented')

PAYLOAD = bytearray(range(1, 10))

VENDOR_GUID = '5e8351d5-1c0d-46fe-a8f4-b52c117bfea7'

RUNTIME_NON_VOLATILE_FILE = 'RUNTIME_NON_VOLATILE_FILE-' + VENDOR_GUID
RUNTIME_VOLATILE_FILE = 'RUNTIME_VOLATILE_FILE-' + VENDOR_GUID
BOOTTIME_NON_VOLATILE_FILE = 'BOOTTIME_NON_VOLATILE_FILE-' + VENDOR_GUID
BOOTTIME_VOLATILE_FILE = 'BOOTTIME_VOLATILE_FILE-' + VENDOR_GUID

if __name__ == '__main__':
    with open(RUNTIME_NON_VOLATILE_FILE, 'wb') as f:
        f.write(Attrs.as_bytes(Attrs.NON_VOLATILE | Attrs.BOOTSERVICE_ACCESS | Attrs.RUNTIME_ACCESS))
        f.write(PAYLOAD)

    with open(RUNTIME_VOLATILE_FILE, 'wb') as f:
        f.write(Attrs.as_bytes(Attrs.BOOTSERVICE_ACCESS | Attrs.RUNTIME_ACCESS))
        f.write(PAYLOAD)

    with open(BOOTTIME_NON_VOLATILE_FILE, 'wb') as f:
        f.write(Attrs.as_bytes(Attrs.NON_VOLATILE | Attrs.BOOTSERVICE_ACCESS))
        f.write(PAYLOAD)

    with open(BOOTTIME_VOLATILE_FILE, 'wb') as f:
        f.write(Attrs.as_bytes(Attrs.BOOTSERVICE_ACCESS))
        f.write(PAYLOAD)

    print("\nWrote variable files:\n\t" + '\n\t'.join([RUNTIME_NON_VOLATILE_FILE, RUNTIME_VOLATILE_FILE, BOOTTIME_NON_VOLATILE_FILE, BOOTTIME_VOLATILE_FILE]))

    print("\n\nTo test, simply:\n\t$ scp *{guid} root@${{HOST}}:/sys/firmware/efi/efivars/".format(guid=VENDOR_GUID))
    print("\nReboot and verify the different attributes:")
    print("\t", RUNTIME_NON_VOLATILE_FILE, "- should be visible from Linux after reboot")
    print("\t", RUNTIME_VOLATILE_FILE, "- should not be visible from Linux after reboot")
    print("\t", BOOTTIME_NON_VOLATILE_FILE, "- should not be visible from Linux after reboot")
    print("\t", BOOTTIME_VOLATILE_FILE, "- should not be visible from Linux after reboot")

