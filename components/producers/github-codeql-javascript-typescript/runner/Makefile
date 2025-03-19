.PHONY: container publish

CONTAINER_REPO=
SMITHY_VERSION=
SOURCE_CODE_REPO=
BUILD_ARCHITECTURE=

DOCKER=docker

container:
	$(DOCKER) build --tag $(CONTAINER_REPO)/components/producers/github-codeql-javascript-typescript/runner:$(SMITHY_VERSION) \
					$$([ "${SOURCE_CODE_REPO}" != "" ] && echo "--label=org.opencontainers.image.source=${SOURCE_CODE_REPO}" ) \
					-f Dockerfile \
					--platform "$(BUILD_ARCHITECTURE)" ../../../.. 1>&2

publish: 
	$(DOCKER) push $(CONTAINER_REPO)/components/producers/github-codeql-javascript-typescript/runner:$(SMITHY_VERSION) 1>&2
