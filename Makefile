include Common.mk

TARGET := uefistored
CC ?= gcc

PKGS += xencontrol          \
        xenstore            \
        xenforeignmemory    \
        xendevicemodel      \
        xenevtchn           \
        xentoolcore

OBJS := $(patsubst %.c,%.o,$(SRCS))

CFLAGS := -I$(shell pwd)/inc
CFLAGS += $(foreach pkg,$(PKGS),$$(pkg-config --cflags $(pkg)))
CFLAGS += -fshort-wchar -fstack-protector -O2
CFLAGS += -Wp,-MD,$(@D)/.$(@F).d -MT $(@D)/$(@F)

INC := $(foreach pkg,$(PKGS),$$(pkg-config --libs $(pkg)))

DEPS     = ./.*.d src/.*.d src/uefi/.*.d

TAG     := $(shell git describe --abbrev=0 --tags)
RELEASE := $(shell echo $(TAG) | tr -d 'v')
ARCHIVE := $(TARGET)-$(RELEASE).tar.gz

all:              ## Build uefistored (same as uefistored target)
all: $(TARGET) $(TARGET)-debug

uefistored:       ## Build uefistored
$(TARGET): src/$(TARGET).c $(OBJS)
	$(CC) -o $@ $< $(CFLAGS) $(OBJS) $(INC)

uefistored-debug: ## Build uefistored with debug symbols
$(TARGET)-debug: CFLAGS += -g -grecord-gcc-switches
$(TARGET)-debug: src/$(TARGET).c $(OBJS)
	$(CC) -o $@ $< $(CFLAGS) $(OBJS) $(INC)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(INC)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
	rm -f $(DEPS)
	$(MAKE) clean -C tests/

.PHONY: tools
tools:
	$(MAKE) -C tools

.PHONY: test
test:             ## Run uefistored unit tests with address sanitizers
	$(MAKE) all -C tests/

.PHONY: install
install: uefistored
install:          ## Install uefistored and secureboot-certs
	mkdir -p $(DESTDIR)/usr/sbin/
	install -m 755 $< $(DESTDIR)/usr/sbin/$<
	install -m 755 scripts/secureboot-certs $(DESTDIR)/usr/sbin/secureboot-certs

.PHONY: deploy
deploy:           ## Deploy uefistored to a host
	scp uefistored root@$(HOST):/usr/sbin/uefistored
	ssh root@$(HOST) -- ln -sf /usr/sbin/uefistored /usr/sbin/varstored

.PHONY: help
help:             ## Display this help
	@printf "\nuefistored - UEFI Secure Boot Support for Xen Guest VMs\n\n"
	@grep -Fh "##" Makefile Docker.mk | grep -Fv grep | sed -e 's/\\$$//' | sed -e 's/##//'
	@printf "\n"

print-%:
	@:$(info $($*))

.PHONY: scan-build
scan-build:       ## Use scan-build for static analysis
	scan-build make all -j$(shell nproc)

.PHONY: archive
archive:          ## Create uefistored-X.Y.Z.tar.gz for release of most recent tag
	git archive --format=tar --prefix=uefistored-$(RELEASE)/ $(TAG) \
		| gzip > $(ARCHIVE)

-include $(DEPS)
include Docker.mk
