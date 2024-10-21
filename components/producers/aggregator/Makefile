.PHONY: container publish

CONTAINER_REPO=
SMITHY_VERSION=
SOURCE_CODE_REPO=
BUILD_ARCHITECTURE=

DOCKER=docker

container:
	$(DOCKER) build --tag $(CONTAINER_REPO)/components/producers/tagger:$(SMITHY_VERSION) \
					--build-arg EXECUTABLE_SRC_PATH=components/producers/aggregator/$(BUILD_ARCHITECTURE)/aggregator-parser \
        			--build-arg EXECUTABLE_TARGET_PATH=components/producers/aggregator/tagger \
					$$([ "${SOURCE_CODE_REPO}" != "" ] && echo "--label=org.opencontainers.image.source=${SOURCE_CODE_REPO}" ) \
					--platform "$(BUILD_ARCHITECTURE)" \
					--file "${BASE_IMAGE_PATH}" ../../../bin 1>&2

publish:
	$(DOCKER) push $(CONTAINER_REPO)/components/producers/tagger:$(SMITHY_VERSION) 1>&2
