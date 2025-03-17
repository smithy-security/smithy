# Developer vars
# The following variables are used to define the developer environment
# e.g. what are the test packages, or the latest tag, these are used by make targets that build things
component_binaries=$(shell find ./components -name main.go | xargs -I'{}' sh -c 'echo $$(dirname {})/bin')
component_containers=$(shell find ./components -name main.go | xargs -I'{}' sh -c 'echo $$(dirname {})/docker')
component_containers_publish=$(component_containers:docker=publish)
protos=$(shell find . -not -path './vendor/*' -name '*.proto')
go_protos=$(protos:.proto=.pb.go)
latest_tag=$(shell git tag --list --sort="-version:refname" | head -n 1)
commits_since_latest_tag=$(shell git log --oneline $(latest_tag)..HEAD | wc -l)
# /components/producers/golang-nancy/examples is ignored as it's an example of a vulnerable go.mod.
GO_TEST_PACKAGES=$(shell find . -path './components/producers/golang-nancy/examples' -prune -o -name 'go.mod' -exec dirname {} \; | sort -u)
VENDOR_DIRS=$(shell find . -type d -name "vendor")
EXCLUDE_VENDOR_PATHS := $(shell echo $(VENDOR_DIRS) | awk '{for (i=1; i<=NF; i++) print "--exclude-path \""$$i"\""}' | tr '\n' ' ')
GO_TEST_OUT_DIR_PATH=$(shell pwd)/tests/output

# Deployment vars
# The following variables are used to define the deployment environment
# e.g. what are the versions of the components, or the container registry, these are used by make targets that deploy things
CONTAINER_REPO=ghcr.io/smithy-security/smithy
SOURCE_CODE_REPO=https://github.com/smithy-security/smithy
SMITHY_DEV_VERSION=$(shell echo $(latest_tag)$$([ $(commits_since_latest_tag) -eq 0 ] || echo "-$$(git log -n 1 --pretty='format:%h')" )$$([ -z "$$(git status --porcelain=v1 2>/dev/null)" ] || echo "-dirty" ))
SMITHY_VERSION=$(shell (echo $(CONTAINER_REPO) | grep -q '^ghcr' && echo $(latest_tag)) || echo $(SMITHY_DEV_VERSION) )
SMITHY_OSS_COMPONENTS_NAME=smithy-security-oss-components
SMITHY_OSS_COMPONENTS_PACKAGE_URL=oci://ghcr.io/smithy-security/smithy/charts/$(SMITHY_OSS_COMPONENTS_NAME)

DOCKER=docker
BUF_CONTAINER=buf:local

export

########################################
############# BUILD TARGETS ############
########################################
.PHONY: components component-binaries cmd/smithyctl/bin protos build publish-component-containers publish-containers smithyctl-image smithyctl-image-publish clean-protos clean

$(component_binaries):
	./scripts/build_component_binary.sh $@

component-binaries: $(component_binaries)

$(component_containers): %/docker: %/bin
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	./scripts/build_component_container.sh $@

components: $(component_containers)

cmd/smithyctl/bin:
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o bin/cmd/$(GOOS)/$(GOARCH)/smithyctl cmd/smithyctl/main.go

smithyctl-image: cmd/smithyctl/bin
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	$(DOCKER) build -t "${CONTAINER_REPO}/smithyctl:${SMITHY_VERSION}" \
		--build-arg GOOS=$(GOOS) \
		--build-arg GOARCH=$(GOARCH) \
		$$([ "${SOURCE_CODE_REPO}" != "" ] && echo "--label=org.opencontainers.image.source=${SOURCE_CODE_REPO}" ) \
		-f containers/Dockerfile.smithyctl . \
		--platform "$(GOOS)/$(GOARCH)"

smithyctl-image-publish: smithyctl-image
	$(DOCKER) push "${CONTAINER_REPO}/smithyctl:${SMITHY_VERSION}"

$(component_containers_publish): %/publish: %/docker
	./scripts/publish_component_container.sh $@

publish-component-containers: $(component_containers_publish)

publish-containers: publish-component-containers smithyctl-image-publish

########################################
######### CODE QUALITY TARGETS #########
########################################
.PHONY: lint install-lint-tools tests go-tests fmt fmt-proto fmt-go install-go-fmt-tools

lint:
# we need to redirect stderr to stdout because Github actions don't capture the stderr lolz
	@reviewdog -fail-level=any -diff="git diff origin/main" -filter-mode=added 2>&1

install-lint-tools:
	GOTOOLCHAIN=$$(go env GOVERSION) go install honnef.co/go/tools/cmd/staticcheck@2024.1.1
	@go install github.com/mgechev/revive@v1.6.0
	@go install github.com/sivchari/containedctx/cmd/containedctx@latest
	@go install github.com/gordonklaus/ineffassign@latest
	@go install github.com/polyfloyd/go-errorlint@latest
	@go install github.com/kisielk/errcheck@latest
	@go install github.com/rhysd/actionlint/cmd/actionlint@latest
	@go install github.com/client9/misspell/cmd/misspell@latest
	@npm ci

install-go-test-tools:
	@go install gotest.tools/gotestsum@latest

go-tests:
	@mkdir -p tests/output
	@for package in $(GO_TEST_PACKAGES); do \
		LISTED_PACKAGES=./...; \
		if [ "$$package" = "." ]; then \
			LISTED_PACKAGES=$$(go list ./... | grep -v "^$$package$$"); \
		fi; \
		(cd $$package && gotestsum --junitfile $(GO_TEST_OUT_DIR_PATH)/unit-tests.xml -- -race -coverprofile $(GO_TEST_OUT_DIR_PATH)/cover.out $$LISTED_PACKAGES) || exit 1; \
	done

go-cover: go-tests
	@go tool cover -html=tests/output/cover.out -o=tests/output/cover.html && open tests/output/cover.html

test: go-tests

install-go-fmt-tools:
	@go install github.com/bufbuild/buf/cmd/buf@v1.28.1
	@go install golang.org/x/tools/cmd/goimports@latest

fmt-go:
	echo "Tidying up Go files"
	$(shell find . -type f -name "*.go" -not -name "*.pb.*" -not -path "*/vendor/*" -not -name "*_mock_test.go" | xargs gofmt -w)
	$(shell find . -type f -name "*.go" -not -name "*.pb.*" -not -path "*/vendor/*" -not -name "*_mock_test.go" -exec goimports -local github.com/smithy-security/smithy -w {} \;)

install-md-fmt-tools:
	@npm ci

fmt-md:
	@echo "Tidying up MD files"
	@npm run format

fmt: fmt-go fmt-proto fmt-md

build-buf-container:
	$(DOCKER) build . -t $(BUF_CONTAINER) -f containers/Dockerfile.buf

run-buf: build-buf-container
	$(eval BUF_TMP_DP_FOLDER:=buf-tmp)
	@if [ ! -d "$(BUF_TMP_DP_FOLDER)" ]; then mkdir $(BUF_TMP_DP_FOLDER); fi
	$(DOCKER) run \
		--volume "$(shell pwd):/workspace" \
		--volume $(BUF_TMP_DP_FOLDER):/tmp \
		--workdir /workspace \
		$(BUF_CONTAINER) \
		$(ARGS)
	@rm -rf $(BUF_TMP_DP_FOLDER)

fmt-proto: build-buf-container
	@echo "Tidying up Proto files"
	$(MAKE) run-buf ARGS="format -w $(EXCLUDE_VENDOR_PATHS)"

lint-proto: build-buf-container
	@echo "Linting Proto files"
	$(MAKE) run-buf ARGS="lint $(EXCLUDE_VENDOR_PATHS)"

generate-proto: build-buf-container
	@echo "Generating Proto files"
	$(MAKE) run-buf ARGS="generate"

dep-update-proto: build-buf-container
	@echo "Updating buf.lock deps"
	$(MAKE) run-buf ARGS="dep update"

########################################
########### RELEASE UTILITIES ##########
########################################
.PHONY: check-branch check-tag-message patch-release-tag new-minor-release-tag new-major-release-tag

check-branch:
	@if [ $$(git branch --show-current | tr -d '\n') != "main" ]; \
	then \
		echo >&2 "you need to be on the main branch"; \
		false; \
	fi

check-tag-message:
	@if [ -z "$(TAG_MESSAGE)" ]; \
	then \
		echo >&2 "you need to set the TAG_MESSAGE environment variable to a non empty string"; \
		false; \
	fi

new-patch-release-tag: SHELL:=/bin/bash
new-patch-release-tag: check-branch check-tag-message
	$(shell \
		read -a number <<< $$(git tag -l | sort -Vr | head -n 1 | sed -E 's/^v([0-9]+)\.([0-9]+)\.([0-9]+)/\1 \2 \3/'); \
		git tag "v$${number[0]}.$${number[1]}.$$(($${number[2]}+1))" -m "${TAG_MESSAGE}"; \
	)

new-minor-release-tag: SHELL:=/bin/bash
new-minor-release-tag: check-branch check-tag-message
	$(shell \
		read -a number <<< $$(git tag -l | sort -Vr | head -n 1 | sed -E 's/^v([0-9]+)\.([0-9]+)\.([0-9]+)/\1 \2 \3/'); \
		git tag "v$${number[0]}.$$(($${number[1]}+1)).0" -m "${TAG_MESSAGE}"; \
	)

new-major-release-tag: SHELL:=/bin/bash
new-major-release-tag: check-branch check-tag-message
	$(shell \
		read -a number <<< $$(git tag -l | sort -Vr | head -n 1 | sed -E 's/^v([0-9]+)\.([0-9]+)\.([0-9]+)/\1 \2 \3/'); \
		git tag "v$$(($${number[0]}+1)).0.0" -m "${TAG_MESSAGE}"; \
	)

# new targets for components and smithyctl
.PHONY: smithyctl/bin component-sdk-version

smithyctl/bin:
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	@cd smithyctl && \
		GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o ../bin/smithyctl/cmd/$(GOOS)/$(GOARCH)/smithyctl main.go

component-sdk-version:
	@if [ -z "$(COMPONENT_TYPE)" ]; then \
		echo "Error: COMPONENT_TYPE is not set"; \
		exit 1; \
	fi
	@if [ -z "$(COMPONENT_NAME)" ]; then \
		echo "Error: COMPONENT_NAME is not set"; \
		exit 1; \
	fi
	@grep 'github.com/smithy-security/smithy/sdk' new-components/$(COMPONENT_TYPE)/$(COMPONENT_NAME)/go.mod | awk '{print $$2}'
