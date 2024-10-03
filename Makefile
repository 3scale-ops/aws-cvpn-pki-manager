
.PHONY: help

TAG	?= local
IMAGE	?= quay.io/3scale/aws-cvpn-pki-manager
CONTAINER_TOOL ?= podman

help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null \
		| awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
		| egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

get-new-release:
	@hack/new-release.sh v$(TAG)

build-all-release: build

push-all-release: push

build-all-latest: build-latest

push-all-latest: push-latest

build-all: build

build:
	${CONTAINER_TOOL} manifest rm $(IMAGE):$(TAG) || echo "No manifest found"
	${CONTAINER_TOOL} manifest create $(IMAGE):$(TAG)
	${CONTAINER_TOOL} build \
		--platform linux/amd64,linux/arm64 \
		--manifest $(IMAGE):$(TAG) . -f Dockerfile

push:
	${CONTAINER_TOOL} manifest push $(IMAGE):$(TAG)

build-latest: build
	${CONTAINER_TOOL} tag $(IMAGE):$(TAG) $(IMAGE):latest

push-latest: build-latest
	${CONTAINER_TOOL} push $(IMAGE):latest