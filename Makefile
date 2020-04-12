varstored: main.c
	gcc -o $@ $<

.PHONY: clean
clean:
	rm varstored

include Env.mk
