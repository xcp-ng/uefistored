# GIT repo dependencies

xcp-ng-build-env/.cloned: GIT_REPO := https://github.com/xcp-ng/xcp-ng-build-env.git
edk2/.cloned: GIT_REPO := https://github.com/xcp-ng-rpms/edk2.git

GIT_REPO_TARGETS :=  xcp-ng-build-env/.cloned edk2/.cloned
XCP_NG_VER=8.1

.PHONY: fetch
fetch: $(GIT_REPO_TARGETS)
	@echo "$@ done!"

.PHONY: docker-build
docker-build: xcp-ng-build-env/.cloned
	cd xcp-ng-build-env && ./build.sh $(XCP_NG_VER)

print-%:
	@:$(info $($*))

%/.cloned:
	git clone $(GIT_REPO)
	touch $@
