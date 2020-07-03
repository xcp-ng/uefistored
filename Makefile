LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))

SRCS := src/backends/filedb.c                                   \
        src/common.c                                            \
        src/xenvariable.c                                       \
        src/serializer.c                                        \
        src/xapi.c                                              \
        src/backends/ramdb.c                                    \
        src/uefitypes.c                                         \
        src/uefi_guids.c                                        \
        src/varnames.c

OBJS := $(patsubst %.c,%.o,$(SRCS))

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
	$(MAKE) clean -C tests/

.PHONY: clean-test
clean-test:
	$(MAKE) clean -C tests/


.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: test
test:
	$(MAKE) -C tests/

.PHONY: test-nosan
test-nosan:
	$(MAKE) test-nosan -C tests/

include Env.mk
