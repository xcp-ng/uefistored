CFLAGS := -Wall

.PHONY: all
all:  XenVariable.o
	@echo "Done!"

%.o: %.c
	gcc -o $@ -c $< -I. $(CFLAGS)
