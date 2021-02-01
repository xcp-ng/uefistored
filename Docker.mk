XCP_NG_VER := 8.1
DOCKER_IMAGE := xcp-ng/xcp-ng-build-env:$(XCP_NG_VER)
DOCKER_ARGS := -v$(PWD):$(PWD) -w $(PWD) -it $(DOCKER_IMAGE)

docker-shell:
	docker run $(DOCKER_ARGS) bash

docker-%:
	docker run $(DOCKER_ARGS) $(notdir $(MAKE)) $* $(MAKEFLAGS)
