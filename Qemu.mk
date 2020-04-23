include Common.mk

QEMU_DIR := qemu/

QEMU_TARGETS := $(QEMU_DIR)hw/i386/xen/xen-hvm.o

.PHONY: qemu
qemu: $(QEMU_TARGETS)
	@echo "Build QEMU hvm"

$(QEMU_DIR)hw/i386/xen/xen-hvm.o: $(QEMU_DIR)hw/i386/xen/xen-hvm.c
	gcc -o $@ -c $< $(INCLUDE) $(LIBS) -Wall
