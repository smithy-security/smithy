.PHONY: image

BUILD_ARCHITECTURE=
COMPONENT_REGISTRY=
COMPONENT_REPOSITORY=
COMPONENT_TAG=
BUILD_LABELS=

image:
	docker build $$([ "${BUILD_ARCHITECTURE}" != "" ] && echo "--platform=${BUILD_ARCHITECTURE}" ) \
				 --label "$(BUILD_LABELS)" \
				 --tag $(COMPONENT_REGISTRY)/$(COMPONENT_REPOSITORY):$(COMPONENT_TAG) \
				 --file Dockerfile .

fmt:
	. .venv/bin/activate && black .

venv:
	python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

tests:
	. ./.venv/bin/activate && pytest .
