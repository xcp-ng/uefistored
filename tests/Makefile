include ../Common.mk

CC := gcc

SRCS := $(patsubst %,../%,$(SRCS))
HDRS := $(shell find . -type f -name '*.h')

LIBS := -lssl -lcrypto -lxml2
CFLAGS += -g -Wall -Werror -fshort-wchar

INC := -I../inc/ -Idata/ -I. -I../libs -Iinc -Imock/ -Isrc/ -I/usr/include/libxml2 
INC += -I./munit/

# Add mocks
TEST_SRCS += mock/XenVariable.c \
             mock/sys/socket.c

# Add test files
TEST_SRCS +=                            \
    src/test_auth.c                     \
    src/test_auth_func.c                \
    src/test_base64.c                   \
    src/test_common.c                   \
    src/test_xen_variable_server.c      \
    src/test_pk.c      \
    src/test_storage.c                  \
    src/test_xapi.c

TEST_SRCS += munit/munit.c

TEST_OBJS := $(patsubst %.c,%.o,$(TEST_SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))

#SANITIZERS := -fsanitize=address -fsanitize=undefined -fsanitize=leak

.PHONY: all
all: test-nosan test
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./test-nosan
	./$<

test: main.c $(OBJS) $(TEST_OBJS) keys/.done $(HDRS)
	$(CC) -o $@ $< $(INC) $(LIBS) $(OBJS) $(TEST_OBJS) $(CFLAGS) $(SANITIZERS)


run-test: test
    $<

test-nosan: src/main.c $(TEST_OBJS) $(OBJS) keys $(HDRS)
	$(CC) -o $@ $< $(INC) $(OBJS) $(TEST_OBJS) $(CFLAGS) $(LIBS)

run-test-nosan: test-nosan
    $<


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
	rm -f $(OBJS) $(TEST_OBJS) test test-nosan
	$(MAKE) $@ -C fuzz/

.PHONY: keys
keys: keys/.done
	@echo "Keys generated"

keys/.done:
	@mkdir -p keys
	@cd keys && ../scripts/create-keys.sh
	@touch $@

.PHONY: print
print:
	@echo "$(OBJS) $(TEST_OBJS)"

.PHONY: fetch
fetch:
	git clone git@github.com:nemequ/munit.git
