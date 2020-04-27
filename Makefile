LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))
OBJS :=
INC :=
CFLAGS := -g -Wall

all: varstored

varstored: main.c $(OBJS)
	gcc -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm varstored $(OBJS)

.PHONY: tools
tools:
	$(MAKE) -C tools

include Env.mk
