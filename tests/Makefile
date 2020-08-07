include ../Common.mk

CC := gcc

SRCS := $(patsubst %,../%,$(SRCS))
HDRS := $(shell find . -type f -name '*.h')

CFLAGS := -g -Wall -lssl -lcrypto -lxml2 -I/usr/include/libxml2 -Werror
INC := -I../inc/ -Idata/ -I. -I../libs -Iinc -I mock/ -Isrc/

# Add mocks
TEST_SRCS += mock/XenVariable.c \
        mock/sys/socket.c

# Add test files
TEST_SRCS += src/test_auth.c             \
        src/test_xapi.c             \
        src/test_xen_variable_server.c      \
        src/test_storage.c            \
        src/edk2/secure_boot.c

TEST_OBJ := $(patsubst %.c,%.o,$(TEST_SRCS))
OBJ := $(patsubst %.c,%.o,$(SRCS))

.PHONY: all
all: test-nosan test
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./test-nosan
	./$<

test: src/main.c $(OBJ) $(TEST_OBJ) keys/.done $(HDRS)
	$(CC) -o $@ $< $(INC) $(OBJ) $(TEST_OBJ) $(CFLAGS) -fsanitize=address -fsanitize=undefined -fsanitize=leak

test-nosan: src/main.c $(TEST_OBJ) $(OBJ) keys $(HDRS)
	$(CC) -o $@ $< $(INC) $(OBJ) $(TEST_OBJ) $(CFLAGS)

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

fuzz-memory: CFLAGS := $(CFLAGS) -fsanitize=fuzzer,memory
fuzz-memory: CC = clang
fuzz-memory: src/fuzz_xen_variable_server.c  $(OBJ)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJ)

fuzz-address: CFLAGS := $(CFLAGS) -fsanitize=fuzzer,address
fuzz-address: CC = clang
fuzz-address: src/fuzz_xen_variable_server.c  $(OBJ)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJ)

fuzz-overflow: CFLAGS := $(CFLAGS) -fsanitize=fuzzer,signed-integer-overflow
fuzz-overflow: CC = clang
fuzz-overflow: src/fuzz_xen_variable_server.c  $(OBJ)
	$(CC) -o $@ $< $(INC) $(CFLAGS) $(OBJ)

.PHONY: valgrind
valgrind: test-nosan
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./test-nosan

%.o: %.c
	$(CC) -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm -f $(OBJ) $(TEST_OBJ) test test-nosan

.PHONY: keys
keys: keys/.done
	@echo "Keys generated"

keys/.done:
	@mkdir -p keys
	@cd keys && ../scripts/create-keys.sh
	@touch $@

print-%:
	@:$(info $($*))
