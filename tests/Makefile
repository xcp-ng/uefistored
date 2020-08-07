include ../Common.mk

CC := gcc

SRCS := $(patsubst %,../%,$(SRCS))
HDRS := $(shell find . -type f -name '*.h')

LIBS := -lssl -lcrypto -lxml2
CFLAGS := -g -Wall -Werror
INC := -I../inc/ -Idata/ -I. -I../libs -Iinc -Imock/ -Isrc/ -I/usr/include/libxml2 

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
	$(CC) -o $@ $< $(INC) $(LIBS) $(OBJ) $(TEST_OBJ) $(CFLAGS) -fsanitize=address -fsanitize=undefined -fsanitize=leak

test-nosan: src/main.c $(TEST_OBJ) $(OBJ) keys $(HDRS)
	$(CC) -o $@ $< $(INC) $(OBJ) $(TEST_OBJ) $(CFLAGS)

.PHONY: valgrind
valgrind: test-nosan
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./test-nosan

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm -f $(OBJ) $(TEST_OBJ) test test-nosan
	$(MAKE) -C fuzz/

.PHONY: keys
keys: keys/.done
	@echo "Keys generated"

keys/.done:
	@mkdir -p keys
	@cd keys && ../scripts/create-keys.sh
	@touch $@

print-%:
	@:$(info $($*))
