CFLAGS := -g -Wall
INC := -I../inc/ -Idata/ -I. -I../libs
OBJ := ../src/parse.o test_xenvar.o test_parse.o mock/XenVariable.o ../src/xenvariable.o \
       ../src/backends/filedb.o ../libs/kissdb/kissdb.o test_xenvariable.o  ../src/serializer.o

.PHONY: all
all: test test-nosan
	./$<
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./test-nosan

test: main.c $(OBJ)
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS) -fsanitize=address -fsanitize=undefined -fsanitize=leak

test-nosan: main.c $(OBJ)
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm $(OBJ) test
