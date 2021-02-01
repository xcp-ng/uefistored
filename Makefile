include Common.mk

TARGET := uefistored
CC ?= gcc

LIBS :=						\
	-lxenstore				\
	-lxenctrl				\
	-lxenforeignmemory		\
	-lxendevicemodel		\
	-lxenevtchn				\
	-lxentoolcore			\
	-lseccomp				\
	-lssl				    \
	-lcrypto				\
	$$(pkg-config --libs libxml-2.0)

OBJS := $(patsubst %.c,%.o,$(SRCS))

CFLAGS = -I$(PWD)/inc
CFLAGS += -Wall -Werror -Wextra -fshort-wchar -fstack-protector -O2 \
		  -fstack-clash-protection
CFLAGS += $$(pkg-config --cflags libxml-2.0)

CFLAGS += -Wp,-MD,$(@D)/.$(@F).d -MT $(@D)/$(@F)
DEPS     = ./.*.d src/.*.d

all:        ## Build uefistored (same as uefistored target)
all: $(TARGET) $(TARGET)-debug

uefistored: ## Build uefistored
$(TARGET): src/$(TARGET).c $(OBJS)
	$(CC) -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

uefistored-debug: ## Build uefistored with debug symbols
$(TARGET)-debug: CFLAGS += -g -grecord-gcc-switches
$(TARGET)-debug: src/$(TARGET).c $(OBJS)
	$(CC) -o $@ $< $(LIBS) $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	$(CC) -o $@ -c $< $(LIBS) $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
	rm -f $(DEPS)

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

-include $(DEPS)
include Docker.mk
