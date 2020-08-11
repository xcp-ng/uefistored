ROOT := ../../
include $(ROOT)Common.mk

CC := clang

BIN_DIR := bin/
SRCS := $(patsubst %,$(ROOT)%,$(SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))
HDRS := $(shell find . -type f -name '*.h')
CFLAGS := -g -lssl -lcrypto -lxml2 -I/usr/include/libxml2 -fsanitize=fuzzer
INC := -I$(ROOT)inc/    \
       -Idata/          \
       -I.              \
       -I$(ROOT)libs    \
       -I$(ROOT)inc     \
       -I$(ROOT)mock/   \
       -I$(ROOT)src/    \
       -I../inc/

TEST_SRCS := $(shell find -type f -name '*.c')

MEM_TESTS := $(patsubst %.c,$(BIN_DIR)%.mem,$(TEST_SRCS))
ADDR_TESTS := $(patsubst %.c,$(BIN_DIR)%.addr,$(TEST_SRCS))
OFLOW_TESTS := $(patsubst %.c,$(BIN_DIR)%.oflow,$(TEST_SRCS))

RM := rm -f
MKDIR := mkdir -p

FUZZ_LONG := 30m
FUZZ_SHORT := 30s

.PHONY: all
all: $(MEM_TESTS) $(ADDR_TESTS) $(OFLOW_TESTS)

$(BIN_DIR)%.mem: %.c $(OBJS)
	$(MKDIR) $(shell dirname $@)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJS) -fsanitize=fuzzer,memory -g
	$(MKDIR) $@.corpus

$(BIN_DIR)%.addr: %.c $(OBJS)
	$(MKDIR) $(shell dirname $@)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJS) -fsanitize=fuzzer,address -g
	$(MKDIR) $@.corpus

$(BIN_DIR)%.oflow: %.c $(OBJS)
	$(MKDIR) $(shell dirname $@)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJS) -fsanitize=fuzzer,signed-integer-overflow -g
	$(MKDIR) $@.corpus


$(BIN_DIR): 
	$(MKDIR) $@

.PHONY: clean
clean:
	$(RM) $(MEM_TESTS) $(ADDR_TESTS) $(OFLOW_TESTS)
	$(RM) -r $(BIN_DIR)
	$(RM) $(OBJS)

%.o: %.c
	$(CC) -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)
