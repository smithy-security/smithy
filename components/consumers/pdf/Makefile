.PHONY: container publish

CONTAINER_REPO=
SMITHY_VERSION=
SOURCE_CODE_REPO=
BUILD_ARCHITECTURE=

DOCKER=docker

container:
	$(eval workdir:=$(shell mktemp -d /tmp/pdf.XXXXXX))
	mkdir -p ${workdir}/components/consumers && \
	cp -r ../../../bin/components/consumers/pdf ${workdir}/components/consumers && \
	cp default.html  ${workdir}/components/consumers/pdf && \
	$(DOCKER) build --tag $(CONTAINER_REPO)/components/consumers/pdf:$(SMITHY_VERSION) \
					--file Dockerfile \
					--platform "$(BUILD_ARCHITECTURE)" \
					--build-arg EXECUTABLE_SRC_PATH=components/consumers/pdf/$(BUILD_ARCHITECTURE)/pdf \
        			--build-arg EXECUTABLE_TARGET_PATH=components/consumers/pdf/pdf \
					$$([ "${SOURCE_CODE_REPO}" != "" ] && echo "--label=org.opencontainers.image.source=${SOURCE_CODE_REPO}" ) \
					${workdir} 1>&2 && \
	rm -rf ${workdir}

publish:
	$(DOCKER) push $(CONTAINER_REPO)/components/consumers/pdf:$(SMITHY_VERSION) 1>&2
