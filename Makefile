LIBS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LINK := $(foreach lib,$(LIBS),-l$(lib))

all: varserviced

varserviced: main.c
	gcc -o $@ $< $(LINK)

.PHONY: clean
clean:
	rm varstored

include Env.mk
