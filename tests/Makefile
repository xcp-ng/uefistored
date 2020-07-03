include ../Common.mk

SRCS := $(patsubst %,../%,$(SRCS))

CFLAGS := -g -Wall -lssl -lcrypto -lxml2 -I/usr/include/libxml2
INC := -I../inc/ -Idata/ -I. -I../libs -Iinc -I mock/ -Isrc/

# Add mocks
SRCS += mock/XenVariable.c \
        mock/sys/socket.c

# Add test files
SRCS += src/test_auth.c             \
        src/test_xapi.c             \
        src/test_xenvariable.c      \
        src/test_ramdb.c            \
        src/edk2/secure_boot.c

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

test: src/main.c $(OBJ) keys/.done
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS) -fsanitize=address -fsanitize=undefined -fsanitize=leak

test-nosan: src/main.c $(OBJ) keys
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS)
	./$@

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm $(OBJ) test test-nosan

.PHONY: keys
keys: keys/.done
	@echo "Keys generated"

keys/.done:
	@mkdir -p keys
	@cd keys && ../scripts/create-keys.sh
	@touch $@

print-%:
	@:$(info $($*))
