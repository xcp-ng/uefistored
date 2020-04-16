CFLAGS := -g

LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))

all: varstored

varstored: main.c
	gcc -o $@ $< $(LIBS) $(CFLAGS)

.PHONY: clean
clean:
	rm varstored

include Env.mk