LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))
OBJS := src/backends/filedb.o src/common.o src/parse.o src/xenvariable.o libs/kissdb/kissdb.o src/serializer.o
INC := -Iinc/ -Ilibs/
CFLAGS := -g -Wall

all: varstored

varstored: src/main.c $(OBJS) 
	gcc -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm varstored $(OBJS)

.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: test
test:
	$(MAKE) -C tests/

include Env.mk
