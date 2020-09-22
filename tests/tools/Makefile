ROOT := ../../
include $(ROOT)Common.mk

CC := gcc

SRCS := $(patsubst %,$(ROOT)%,$(SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))
HDRS := $(shell find . -type f -name '*.h')

# Also use:
# -fsanitize=address
# -fsanitize=undefined
CFLAGS := -g -lssl -lcrypto -lxml2 -I/usr/include/libxml2 -fshort-wchar -fsanitize=leak
INC := -I$(ROOT)inc/    \
       -Idata/          \
       -I.              \
       -I$(ROOT)libs    \
       -I$(ROOT)inc     \
       -I$(ROOT)mock/   \
       -I$(ROOT)src/    \
       -I../inc/

TEST_SRCS := $(shell find -type f -name '*.c')

RM := rm -f
MKDIR := mkdir -p

.PHONY: all
all: server

server: server.c $(OBJS)
	$(CC) -o $@ $< $(OBJS) $(INC) $(CFLAGS)

.PHONY: clean
clean:
	$(RM) server $(OBJS)

%.o: %.c
	$(CC) -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)
