# Developer vars
# The following variables are used to define the developer environment
# e.g. what are the test packages, or the latest tag, these are used by make targets that build things
latest_tag=$(shell git tag --list --sort="-version:refname" | head -n 1)
commits_since_latest_tag=$(shell git log --oneline $(latest_tag)..HEAD | wc -l)
# /components/producers/golang-nancy/examples is ignored as it's an example of a vulnerable go.mod.
go_mod_paths=$(shell find . -not -path './deprecated-components/*' -name 'go.mod' | sort -u)
go_test_paths=$(go_mod_paths:go.mod=go-tests)
go_fmt_paths=$(go_mod_paths:go.mod=go-fmt)
go_component_mod_paths=$(shell find ./components -not -path './deprecated-components/*' -name 'go.mod' | sort -u)
go_sdk_lib_update=$(go_component_mod_paths:go.mod=go-sdk-update)
component_root_directories=$(shell find ./components -type d -regextype posix-extended -regex "./components/(targets|scanners|enrichers|filters|reporters)/[a-z-]+")
component_patch_tags=$(component_root_directories:=/patch-tag)
component_minor_tags=$(component_root_directories:=/minor-tag)
component_major_tags=$(component_root_directories:=/major-tag)
VENDOR_DIRS=$(shell find . -type d -name "vendor")
EXCLUDE_VENDOR_PATHS := $(shell echo $(VENDOR_DIRS) | awk '{for (i=1; i<=NF; i++) print "--exclude-path \""$$i"\""}' | tr '\n' ' ')
go_test_out_dir=$(shell pwd)/tests/output

# Deployment vars
# The following variables are used to define the deployment environment
# e.g. what are the versions of the components, or the container registry, these are used by make targets that deploy things
CONTAINER_REPO=ghcr.io/smithy-security/smithy
SOURCE_CODE_REPO=https://github.com/smithy-security/smithy
SMITHY_DEV_VERSION=$(shell echo $(latest_tag)$$([ $(commits_since_latest_tag) -eq 0 ] || echo "-$$(git log -n 1 --pretty='format:%h')" )$$([ -z "$$(git status --porcelain=v1 2>/dev/null)" ] || echo "-dirty" ))
SMITHY_VERSION=$(shell (echo $(CONTAINER_REPO) | grep -q '^ghcr' && echo $(latest_tag)) || echo $(SMITHY_DEV_VERSION) )
SMITHY_OSS_COMPONENTS_NAME=smithy-security-oss-components

CTR_CLI=docker
BUF_CONTAINER=buf:local

export

########################################
######### CODE QUALITY TARGETS #########
########################################
.PHONY: lint install-lint-tools tests test-go fmt fmt-proto fmt-go install-go-fmt-tools

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

$(go_test_paths):
	@mkdir -p tests/output
	@echo "============== running go tests for package $$(dirname $@) =============="
	@cd $$(dirname $@) && gotestsum --junitfile $(go_test_out_dir)/unit-tests.xml -- -race -coverprofile $(go_test_out_dir)/cover.out ./...

test-go: $(go_test_paths)

go-cover: go-tests
	@go tool cover -html=tests/output/cover.out -o=tests/output/cover.html && open tests/output/cover.html

tests: test-go

install-go-fmt-tools:
	@go install github.com/bufbuild/buf/cmd/buf@v1.28.1
	@go install golang.org/x/tools/cmd/goimports@v0.31.0

$(go_fmt_paths):
	@echo "============== Tidying up Go files for package $$(dirname $@) =============="
	@find $$(dirname $@) -type f -name "*.go" -not -name "*.pb.*" -not -path "*/vendor/*" -not -name "*_mock_test.go" | xargs gofmt -w
	@find $$(dirname $@) -type f -name "*.go" -not -name "*.pb.*" -not -path "*/vendor/*" -not -name "*_mock_test.go" -exec goimports -local github.com/smithy-security/smithy/$$(dirname $@) -w {} \;

fmt-go: $(go_fmt_paths)

install-md-fmt-tools:
	@npm ci

fmt-md:
	@echo "Tidying up MD files"
	@npm run format

fmt: fmt-go fmt-proto fmt-md

build-buf-container:
	$(CTR_CLI) build . -t $(BUF_CONTAINER) -f containers/Dockerfile.buf

run-buf: build-buf-container
	$(eval BUF_TMP_DP_FOLDER:=buf-tmp)
	@if [ ! -d "$(BUF_TMP_DP_FOLDER)" ]; then mkdir $(BUF_TMP_DP_FOLDER); fi
	$(CTR_CLI) run \
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

$(component_patch_tags): SHELL:=/bin/bash
$(component_patch_tags): check-branch check-tag-message
	$(shell \
		component_dir=$$(dirname $@); \
		read -a number <<< $$(git tag -l | grep -E "^$${component_dir}" | sort -Vr | head -n 1 | sed -E "s@^$${component_dir}/v([0-9]+)\.([0-9]+)\.([0-9]+)@\1 \2 \3@"); \
		commit_tag="$${component_dir}/v$${number[0]}.$${number[1]}.$$(($${number[2]}+1))"; \
		echo "tagging commit with $${commit_tag}" > /dev/stderr; \
		git tag "$${commit_tag}" -m "${TAG_MESSAGE}"; \
	)

$(component_minor_tags): SHELL:=/bin/bash
$(component_minor_tags): check-branch check-tag-message
	$(shell \
		component_dir=$$(dirname $@); \
		read -a number <<< $$(git tag -l | grep -E "^$${component_dir}" | sort -Vr | head -n 1 | sed -E "s@^$${component_dir}/v([0-9]+)\.([0-9]+)\.([0-9]+)@\1 \2 \3@"); \
		commit_tag="$${component_dir}/v$${number[0]}.$$(($${number[1]}+1)).0"; \
		echo "tagging commit with $${commit_tag}" > /dev/stderr; \
		git tag "$${commit_tag}" -m "${TAG_MESSAGE}"; \
	)

$(component_major_tags): SHELL:=/bin/bash
$(component_major_tags): check-branch check-tag-message
	$(shell \
		component_dir=$$(dirname $@); \
		read -a number <<< $$(git tag -l | grep -E "^$${component_dir}" | sort -Vr | head -n 1 | sed -E "s@^$${component_dir}/v([0-9]+)\.([0-9]+)\.([0-9]+)@\1 \2 \3@"); \
		commit_tag="$${component_dir}/v$$(($${number[0]}+1)).0.0"; \
		echo "tagging commit with $${commit_tag}" > /dev/stderr; \
		git tag "$${commit_tag}" -m "${TAG_MESSAGE}"; \
	)

# new targets for components and smithyctl
.PHONY: smithyctl/bin component-sdk-version bump-sdk-version

smithyctl/bin:
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	@cd smithyctl && \
		GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o ../bin/smithyctl/cmd/$(GOOS)/$(GOARCH)/smithyctl main.go

component-sdk-version:
	@if [ -z "$(COMPONENT_DIR)" ]; then \
		echo "Error: COMPONENT_DIR is not set"; \
		false; \
	fi
	@if [ -f  $(COMPONENT_DIR)/go.mod ]; then \
		grep 'github.com/smithy-security/smithy/sdk' $(COMPONENT_DIR)/go.mod | awk '{print $$2}'; \
	else \
		git tag -l | grep sdk | sort -r | head -n 1 | sed 's/sdk\///'; \
	fi

$(go_sdk_lib_update):
	@if [ -z "$(SDK_VERSION)" ]; then \
		echo "Error: SDK_VERSION is not set. Use SDK_VERSION=vX.X.X make bump-sdk-version"; \
		false; \
	fi
	@echo "============== Updating SDK library for $@ to $(SDK_VERSION) =============="
	@if ! $$(grep "github.com/smithy-security/smithy/sdk" $$(dirname $@)/go.mod > /dev/null); then \
		echo "component $$(dirname $@) doesn't have a dependency on the Smithy SDK"; \
	else \
		cd $$(dirname $@) && go get github.com/smithy-security/smithy/sdk@$(SDK_VERSION) && go mod vendor; \
	fi

# Bumps the SDK to a specified version and skips
# the github.com/smithy-security/smithy/sdk module as well as the root one.
bump-sdk-version: $(go_sdk_lib_update)
	@echo "============== SDK version update complete =============="
