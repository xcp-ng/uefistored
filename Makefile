include Common.mk

LIB_DEPS :=	\
	xenstore \
	xenctrl \
	xenforeignmemory \
	xendevicemodel \
	xenevtchn \
	xentoolcore

LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))

OBJS := $(patsubst %.c,%.o,$(SRCS))

INC := -Iinc/ -Ilibs/
CFLAGS := -g -Wall -Werror -lssl -lcrypto -lxml2 -I/usr/include/libxml2

all:        ## Build varstored (same as varstored target)
all: varstored


varstored:  ## Build varstored
varstored: src/main.c $(OBJS)
	gcc -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	gcc -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm -f varstored $(OBJS)

.PHONY: clean-test
clean-test:
	$(MAKE) clean -C tests/


.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: test
test:       ## Run varstored unit tests with address sanitizers
	$(MAKE) -C tests/
	cd tests && ./$@

.PHONY: test-nosan
test-nosan: ## Run varstored unit tests without address sanitizers
	$(MAKE) test-nosan -C tests/
	cd tests && ./$@

.PHONY: deploy
deploy:     ## Deploy varstored to a XCP-ng host
	scripts/deploy.sh

.PHONY: help
help:
	@printf "\nvarstored - UEFI Secure Boot support for Guest VMs\n\n"
	@fgrep -h "##" Makefile Env.mk | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
	@printf "\n"

include Env.mk
