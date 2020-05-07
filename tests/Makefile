CFLAGS := -g
INC := -I../inc/ -Idata/ -I. -I../libs
OBJ := ../src/parse.o test_xenvar.o test_parse.o mock/XenVariable.o ../src/xenvariable.o  ../src/backends/filedb.o ../libs/kissdb/kissdb.o test_xenvariable.o 

.PHONY: all
all: test
	./$<
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--verbose \
		--log-file=valgrind-out.txt \
		./$<

test: main.c $(OBJ)
	gcc -o $@ $< $(INC) $(OBJ) $(CFLAGS)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm $(OBJ) test
