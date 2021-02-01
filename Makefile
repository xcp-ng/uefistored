include Common.mk

LIB_DEPS :=				\
	xenstore			\
	xenctrl				\
	xenforeignmemory	\
	xendevicemodel		\
	xenevtchn			\
	xentoolcore			\
	seccomp				\
	ssl				    \
	crypto				\
	xml2

CC ?= gcc
LIBS := $(foreach lib,$(LIB_DEPS),-l$(lib))
OBJS := $(patsubst %.c,%.o,$(SRCS))
INC := -Iinc/ -Ilibs/ -I/usr/include/libxml2

CFLAGS += -Wall -Werror -Wextra -fshort-wchar -fstack-protector -O2 \
		  -fstack-clash-protection

all:        ## Build uefistored (same as uefistored target)
all: uefistored uefistored-debug


uefistored: ## Build uefistored
uefistored: src/main.c $(OBJS)
	$(CC) -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

uefistored-debug: CFLAGS += -g -grecord-gcc-switches
uefistored-debug: ## Build uefistored with debug symbols
uefistored-debug: src/main.c $(OBJS)
	$(CC) -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	$(CC) -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm -f uefistored $(OBJS)

.PHONY: clean-test
clean-test:
	$(MAKE) clean -C tests/


.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: test
test:       ## Run uefistored unit tests with address sanitizers
	$(MAKE) -C tests/
	cd tests && ./$@

.PHONY: test-nosan
test-nosan: ## Run uefistored unit tests without address sanitizers
	$(MAKE) test-nosan -C tests/
	cd tests && ./$@

.PHONY: install
install: uefistored

install:    ## Install uefistored
	mkdir -p $(DESTDIR)/usr/sbin/
	cp $< $(DESTDIR)/usr/sbin/$<

.PHONY: deploy
deploy:     ## Deploy uefistored to a XCP-ng host
	scripts/deploy.sh

.PHONY: help
help:
	@printf "\nuefistored - UEFI Secure Boot support for Guest VMs\n\n"
	@fgrep -h "##" Makefile Env.mk | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
	@printf "\n"


print-%:
	@:$(info $($*))

include Docker.mk
