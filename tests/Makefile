INC := -I../inc -Idata/

OBJ := ../src/parse.o

.PHONY: all
all: test
	./$<

test: test_parse.c $(OBJ)
	gcc -o $@ $< $(INC) $(OBJ)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)
