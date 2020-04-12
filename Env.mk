# GIT repo dependencies
GIT_REPO_TARGETS :=  xcp-ng-build-env/.cloned

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
xcp-ng-build-env/.cloned: GIT_REPO := https://github.com/beshleman/xcp-ng-build-env.git

%/.cloned:
	git clone $(GIT_REPO)
	touch $@

docker-shell:
	docker run $(DOCKER_ARGS) bash

docker-%:
	docker run $(DOCKER_ARGS) $(notdir $(MAKE)) $* $(MAKEFLAGS)
