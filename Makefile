LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))

INC := -I inc/
OBJS := src/xen-hvm.o src/common.o
CFLAGS := -g -Wall

all: varstored tools

varstored: src/main.c $(OBJS)
	gcc -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm varstored $(OBJS)

.PHONY: tools
tools:
	make -C tools

include Env.mk
