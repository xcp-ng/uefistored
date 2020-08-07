include ../Common.mk

CC := clang

SRCS := $(patsubst %,../%,$(SRCS))
OBJ := $(patsubst %.c,%.o,$(SRCS))
HDRS := $(shell find . -type f -name '*.h')
CFLAGS := -g -lssl -lcrypto -lxml2 -I/usr/include/libxml2
INC := -I../inc/ -Idata/ -I. -I../libs -Iinc -I mock/ -Isrc/

FUZZ_LONG := 30m
FUZZ_SHORT := 30s

.PHONY: fuzz-all
fuzz-all: fuzz-memory fuzz-address fuzz-overflow
	timeout --preserve-status $(FUZZ_LONG) ./fuzz-memory
	timeout --preserve-status $(FUZZ_LONG) ./fuzz-address
	timeout --preserve-status $(FUZZ_LONG) ./fuzz-overflow

.PHONY: fuzz-short
fuzz-short: fuzz-memory fuzz-address fuzz-overflow
	timeout --preserve-status $(FUZZ_SHORT) ./fuzz-memory
	timeout --preserve-status $(FUZZ_SHORT) ./fuzz-address
	timeout --preserve-status $(FUZZ_SHORT) ./fuzz-overflow

fuzz-memory: src/fuzz_xen_variable_server.c  $(OBJ)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJ) -fsanitize=fuzzer,memory -g

fuzz-address: src/fuzz_xen_variable_server.c  $(OBJ)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJ) -fsanitize=fuzzer,address -g

fuzz-overflow: src/fuzz_xen_variable_server.c  $(OBJ)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJ) -fsanitize=fuzzer,signed-integer-overflow -g

%.o: %.c
	$(CC) -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)
