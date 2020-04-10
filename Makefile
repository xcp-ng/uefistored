.PHONY: fetch
fetch: xcp-ng-build-env/.cloned
	@echo "$@ done!"

xcp-ng-build-env/.cloned:
	git clone https://github.com/xcp-ng/xcp-ng-build-env.git
	touch $@

.PHONY: docker-build
docker-build: xcp-ng-build-env/.cloned
	cd xcp-ng-build-env && ./build.sh 8.1

print-%:
	@:$(info $($*))
