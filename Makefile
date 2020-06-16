LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))
OBJS := src/backends/filedb.o src/common.o src/xenvariable.o    \
        libs/kissdb/kissdb.o src/serializer.o src/xapi.o        \
        src/auth_service.o src/auth.o        \
        src/pkcs7_verify.o  src/CryptSha256.o     \
        src/backends/ramdb.o src/uefitypes.o src/uefi_guids.o src/varnames.o

INC := -Iinc/ -Ilibs/
CFLAGS := -g -Wall -lssl -lcrypto -lxml2 -I/usr/include/libxml2

all: varstored

varstored: src/main.c $(OBJS) 
	gcc -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm varstored $(OBJS)
	$(MAKE) -C tests/

.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: test
test:
	$(MAKE) -C tests/

.PHONY: test-nosan
test-nosan:
	$(MAKE) -C tests/

include Env.mk
