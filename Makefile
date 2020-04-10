# GIT repo dependencies
GIT_REPO_TARGETS :=  xcp-ng-build-env/.cloned edk2/.cloned

# EDK2 uses the 8.1 build env
XCP_NG_VER := 8.1
DOCKER_IMAGE := xcp-ng/xcp-ng-build-env:$(XCP_NG_VER)
DOCKER_ARGS := -v$(PWD):$(PWD) -w $(PWD) -it $(DOCKER_IMAGE)

.PHONY: fetch
fetch: $(GIT_REPO_TARGETS)
	@echo "$@ done!"

.PHONY: docker-build
docker-build: xcp-ng-build-env/.cloned
	cd xcp-ng-build-env && ./build.sh $(XCP_NG_VER)

print-%:
	@:$(info $($*))

# Generic GIT repo clones
xcp-ng-build-env/.cloned: GIT_REPO := https://github.com/xcp-ng/xcp-ng-build-env.git

%/.cloned:
	git clone $(GIT_REPO)
	touch $@

# Special GIT repo clones
edk2/.cloned:
	git clone https://github.com/xcp-ng-rpms/edk2.git
	cd edk2 && git lfs install && git lfs fetch && git lfs checkout
	touch $@


docker-shell:
	docker run $(DOCKER_ARGS) bash

docker-%:
	docker run $(DOCKER_ARGS) $(notdir $(MAKE)) $(MAKE) $* $(MAKEFLAGS)

.PHONY: edk2
edk2:
	cd edk2 && git lfs install
	mkdir -p /root/rpmbuild/{SOURCES,SPECS}
	cp edk2/SOURCES/* /root/rpmbuild/SOURCES/
	cp edk2/SPECS/* /root/rpmbuild/SPECS/
	rpmbuild -ba edk2/SPECS/edk2.spec
