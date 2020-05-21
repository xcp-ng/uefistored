CFLAGS := -g -Wall -lssl -lcrypto
INC := -I../inc/ -Idata/ -I. -I../libs -Iinc
OBJ := mock/XenVariable.o ../src/xenvariable.o ../src/xapi_nvram.o \
       ../src/backends/filedb.o ../libs/kissdb/kissdb.o ../src/serializer.o \
       ../src/common.o

OBJ += src/test_xenvariable.o src/test_xapi_nvram.o

.PHONY: all
all: test test-nosan
	./$<
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./test-nosan

test: src/main.c $(OBJ)
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS) -fsanitize=address -fsanitize=undefined -fsanitize=leak

test-nosan: src/main.c $(OBJ)
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm $(OBJ) test
