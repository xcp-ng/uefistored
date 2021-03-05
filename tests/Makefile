include ../Common.mk

# Override to omit unused libs (i.e., xen libs)
LDFLAGS := $$(pkg-config --libs libxml-2.0)     \
            -lseccomp                           \
            -lssl                               \
            -lcrypto

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
    src/test_common.c                   \
    src/test_xen_variable_server.c      \
    src/test_pk.c      \
    src/test_kek.c      \
    src/test_db.c      \
    src/test_xapi.c

MUNIT_SRCS += munit/munit.c

TEST_OBJS := $(patsubst %.c,%.o,$(TEST_SRCS))
MUNIT_OBJS := $(patsubst %.c,%.o,$(MUNIT_SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))

SANTIZERS :=

ifeq ($(ASAN),1)
 SANITIZERS = -fsanitize=address
endif

.PHONY: all
all: scan-build valgrind asan
	@printf '\n\n\x1B[32mvalgrind, ASAN, scan-build tests all passed\n\n\x1B[0m'

.PHONY: scan-build
scan-build:
	$(MAKE) clean
	scan-build --status-bugs make $(TEST_OBJS) -j$(shell nproc)

.PHONY: asan
asan:
	$(MAKE) clean
	ASAN=1 $(MAKE) test
	ASAN_OPTIONS=detect_leaks=1 ./test

.PHONY: valgrind
valgrind: clean test
	valgrind --leak-check=full \
			--show-leak-kinds=all \
			--track-origins=yes \
			--error-exitcode=1 \
			./test

test: test.c $(OBJS) $(TEST_OBJS) $(HDRS) $(MUNIT_OBJS)
	$(CC) -o $@ $< $(INC) $(LIBS) $(OBJS) \
		$(TEST_OBJS) $(MUNIT_OBJS) $(CFLAGS) $(SANITIZERS) \
		$(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC) $(SANITIZERS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TEST_OBJS) $(MUNIT_OBJS) test test-nosan
	$(MAKE) $@ -C fuzz/

.PHONY: print
print:
	@echo "$(OBJS) $(TEST_OBJS)"

.PHONY: fetch
fetch:
	git clone https://github.com/nemequ/munit.git
