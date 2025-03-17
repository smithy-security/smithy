.PHONY: image

BUILD_ARCHITECTURE=
COMPONENT_REGISTRY=
COMPONENT_REPOSITORY=
COMPONENT_TAG=

image:
	docker build $$([ "${BUILD_ARCHITECTURE}" != "" ] && echo "--platform=${BUILD_ARCHITECTURE}" ) \
				 --label "$(BUILD_LABELS)" \
				 --tag $(COMPONENT_REGISTRY)/$(COMPONENT_REPOSITORY):$(COMPONENT_TAG) \
				 --file Dockerfile .
