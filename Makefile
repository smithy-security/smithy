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

CTR_CLI=docker
BUF_CONTAINER=buf:local
REVIEWDOG_EXTRA_FLAGS=


export

########################################
######### CODE QUALITY TARGETS #########
########################################

.PHONY: lint install-lint-tools tests test-go fmt fmt-proto fmt-go install-go-fmt-tools py-tests py-tests-sdk-python update-poetry-pkgs-sdk-python fmt-py-sdk-python py-lint py-lint-sdk-python 

install-misspell:
	@go install github.com/client9/misspell/cmd/misspell@latest

install-reviewdog:
	@go install github.com/reviewdog/reviewdog/cmd/reviewdog@latest

py-lint-sdk-python: update-poetry-pkgs-sdk-python install-misspell install-reviewdog
	@reviewdog -fail-level=error $$([ "${CI}" = "true" ] && echo "-reporter=github-pr-review") -diff="git diff origin/main" -filter-mode=added -tee -runners black,misspell $(REVIEWDOG_EXTRA_FLAGS)


py-lint: py-lint-sdk-python

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

cover-go: test-go
	@go tool cover -html=tests/output/cover.out -o=tests/output/cover.html && open tests/output/cover.html

update-poetry-pkgs-sdk-python:
	@poetry --directory sdk/python install --with dev

py-tests-sdk-python: update-poetry-pkgs-sdk-python
	@poetry --directory sdk/python run -- pytest --capture no ./tests

py-tests: py-tests-sdk-python

tests: test-go

install-go-fmt-tools:
	@go install github.com/bufbuild/buf/cmd/buf@v1.45.0
	@go install golang.org/x/tools/cmd/goimports@v0.31.0

$(go_fmt_paths):
	@echo "============== Tidying up Go files for package $$(dirname $@) =============="
	@find $$(dirname $@) -type f -name "*.go" -not -name "*.pb.*" -not -path "*/vendor/*" -not -name "*mock*.go" | xargs gofmt -w
	@find $$(dirname $@) -type f -name "*.go" -not -name "*.pb.*" -not -path "*/vendor/*" -not -name "*mock*.go" -exec goimports -local github.com/smithy-security/smithy/$$(dirname $@) -w {} \;

fmt-go: $(go_fmt_paths)

fmt-py-sdk-python: update-poetry-pkgs-sdk-python
	@echo "Tidying up Python files"
	@poetry --directory sdk/python run -- black .

fmt-py: fmt-py-sdk-python

install-md-fmt-tools:
	@npm ci

fmt-md:
	@echo "Tidying up MD files"
	@npm run format

fmt: fmt-go fmt-proto fmt-md

build-buf-container:
	$(CTR_CLI) build . -t $(BUF_CONTAINER) -f containers/Dockerfile.buf

run-buf: build-buf-container
	$(CTR_CLI) run \
		--volume "$(shell pwd):/workspace" \
		--workdir /workspace \
		--user $(shell id -u) \
		$(BUF_CONTAINER) \
		$(ARGS)

fmt-proto: build-buf-container generate-proto
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
.PHONY: check-branch check-tag-message

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

########################################
############## SDK HELPERS #############
########################################
# new targets for components and smithyctl
.PHONY: smithyctl/bin component-sdk-version bump-sdk-version

smithyctl/bin:
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	$(eval SMITHYCTL_VERSION:=development)
	@cd smithyctl && \
		GOOS=$(GOOS) \
		GOARCH=$(GOARCH) \
			go build \
				-ldflags "-X github.com/smithy-security/smithy/smithyctl/command/version.SmithyCTLVersion=${SMITHYCTL_VERSION} -s -w" \
				-trimpath \
				-o ../bin/smithyctl/cmd/$(GOOS)/$(GOARCH)/smithyctl main.go

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
		cd $$(dirname $@); \
		go get github.com/smithy-security/smithy/sdk@$(SDK_VERSION); \
		go mod tidy; \
		go mod vendor; \
	fi

# Bumps the SDK to a specified version and skips
# the github.com/smithy-security/smithy/sdk module as well as the root one.
bump-sdk-version: $(go_sdk_lib_update)
	@echo "============== SDK version update complete =============="