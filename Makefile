go_mod_paths:=$(shell find . -name 'go.mod' | sort -u)
go_component_mod_paths:=$(shell find ./components -name 'go.mod' | sort -u)
go_sdk_lib_update:=$(go_component_mod_paths:go.mod=go-sdk-update)
go_dep_update:=$(go_component_mod_paths:go.mod=go-dep-update)
component_root_directories:=$(shell find ./components/targets ./components/scanners ./components/enrichers ./components/reporters -maxdepth 1 -mindepth 1 -type d )
component_patch_tags:=$(component_root_directories:=/patch-tag)
component_minor_tags:=$(component_root_directories:=/minor-tag)
component_major_tags:=$(component_root_directories:=/major-tag)
VENDOR_DIRS:=$(shell find . -type d -name "vendor")
EXCLUDE_VENDOR_PATHS:=$(shell echo $(VENDOR_DIRS) | awk '{for (i=1; i<=NF; i++) print "--exclude-path \""$$i"\""}' | tr '\n' ' ')
go_test_out_dir:=$(shell pwd)/tests/output

# Deployment vars
# The following variables are used to define the deployment environment
# e.g. what are the versions of the components, or the container registry, these are used by make targets that deploy things
CONTAINER_REPO=ghcr.io/smithy-security/smithy
SOURCE_CODE_REPO=https://github.com/smithy-security/smithy

CTR_CLI=docker
BUF_CONTAINER=buf:local
REVIEWDOG_EXTRA_FLAGS=


export

########################################
######### CODE QUALITY TARGETS #########
########################################

.PHONY: lint install-lint-tools tests test-go fmt fmt-proto fmt-go install-go-fmt-tools \
		py-tests py-tests-sdk-python update-poetry-pkgs-sdk-python fmt-py-sdk-python \
		py-lint py-lint-sdk-python

list-module-paths:
	@find . -name 'go.mod' | tr ' ' '\n' | sed 's/^\.\///' | sed 's/go.mod//' | sort -u | xargs -I{} echo "$$(pwd)/{}"

install-misspell:w
	@go install github.com/client9/misspell/cmd/misspell@latest

install-reviewdog:
	@go install github.com/reviewdog/reviewdog/cmd/reviewdog@latest

py-lint-sdk-python: update-poetry-pkgs-sdk-python install-misspell install-reviewdog
	@reviewdog -fail-level=error $$([ "$${CI}" = "true" ] && echo "-reporter=github-pr-review") -diff="git diff origin/main" -filter-mode=added -tee -runners black,misspell $(REVIEWDOG_EXTRA_FLAGS)

py-lint: py-lint-sdk-python

go_errchecks:=$(go_mod_paths:go.mod=go-errcheck)

$(go_errchecks):
	@cd $$(dirname $@) && errcheck -asserts -blank $$(go list ./... | grep -v "/gen/") | xargs -r -0 -d'\n' -I{} echo "$$(dirname $@)/{}"

go-lint-errchecks: $(go_errchecks)

go_errorlint:=$(go_mod_paths:go.mod=go-errorlint)

$(go_errorlint):
	@cd $$(dirname $@) && go-errorlint -errorf-multi -errorf -test $$(go list ./... | grep -v "/gen/") || true

go-lint-errorlint: $(go_errorlint)

go_ineffassign:=$(go_mod_paths:go.mod=go-ineffassign)

$(go_ineffassign):
	@cd $$(dirname $@) && ineffassign $$(go list ./... | grep -v "/gen/") || true

go-lint-ineffassign: $(go_ineffassign)

go_containedctx:=$(go_mod_paths:go.mod=go-containedctx)

$(go_containedctx):
	@cd $$(dirname $@) && go vet -vettool=$$(which containedctx) $$(go list ./... | grep -v "/gen/")

go-lint-containedctx: $(go_containedctx)

go_vet:=$(go_mod_paths:go.mod=go-vet)

$(go_vet):
	@cd $$(dirname $@) && go vet $$(go list ./... | grep -v "/gen/") 2>&1 | grep -v '#' | xargs -r -0 -d'\n' -I{} echo "$$(dirname $@)/{}" || true

go-lint-vet: $(go_vet)

go_staticcheck:=$(go_mod_paths:go.mod=go-staticcheck)

$(go_staticcheck):
	@cd $$(dirname $@) && staticcheck -checks "all,-SA1019,-ST1000" $$(go list ./... | grep -v "/gen/") | sed 's/\t//' | xargs -r -0 -d'\n' -I{} echo "$$(dirname $@)/{}" || true

go-lint-staticcheck: $(go_staticcheck)

go_revive:=$(go_mod_paths:go.mod=go-revive)

$(go_revive):
	CONFIG_FILE="$$(pwd)/revive.toml" && cd $$(dirname $@) && revive -config $${CONFIG_FILE} ./... | grep -v "^$$" | xargs -r -0 -d'\n' -I{} echo "$$(dirname $@)/{}" || true

go-lint-revive: $(go_revive)

lint:
# we need to redirect stderr to stdout because GitHub actions don't capture the stderr lolz
	@reviewdog -fail-level=any $$([ "$${CI}" = "true" ] && echo "-reporter=github-pr-review") -diff="git diff origin/main" -tee -filter-mode=added 2>&1

install-lint-tools:
	GOTOOLCHAIN=$$(go env GOVERSION) go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
	@go install github.com/mgechev/revive@v1.6.0
	@go install github.com/sivchari/containedctx/cmd/containedctx@v1.0.3
	@go install github.com/gordonklaus/ineffassign@v0.2.0
	@go install github.com/polyfloyd/go-errorlint@v1.8.0
	@go install github.com/kisielk/errcheck@v1.9.0
	@go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
	@go install github.com/client9/misspell/cmd/misspell@v0.3.4
	@npm ci

install-go-test-tools:
	@go install gotest.tools/gotestsum@latest

go_test_paths:=$(go_mod_paths:go.mod=go-tests)

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

go_fmt_paths:=$(go_mod_paths:go.mod=go-fmt)

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

.PHONY: check-branch check-tag-message bump-all-patch-tags bump-all-minor-tags bump-all-major-tags

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
		commit_tag="$${component_dir}/v$${number[0]:-0}.$${number[1]:-0}.$$(($${number[2]}+1))"; \
		echo "tagging commit with $${commit_tag}" > /dev/stderr; \
		git tag "$${commit_tag}" -m "${TAG_MESSAGE}"; \
	)

bump-all-patch-tags: check-branch check-tag-message $(component_patch_tags)

$(component_minor_tags): SHELL:=/bin/bash
$(component_minor_tags): check-branch check-tag-message
	$(shell \
		component_dir=$$(dirname $@); \
		read -a number <<< $$(git tag -l | grep -E "^$${component_dir}" | sort -Vr | head -n 1 | sed -E "s@^$${component_dir}/v([0-9]+)\.([0-9]+)\.([0-9]+)@\1 \2 \3@"); \
		commit_tag="$${component_dir}/v$${number[0]:-0}.$$(($${number[1]}+1)).0"; \
		echo "tagging commit with $${commit_tag}" > /dev/stderr; \
		git tag "$${commit_tag}" -m "${TAG_MESSAGE}"; \
	)

bump-all-minor-tags: check-branch check-tag-message $(component_minor_tags)

$(component_major_tags): SHELL:=/bin/bash
$(component_major_tags): check-branch check-tag-message
	$(shell \
		component_dir=$$(dirname $@); \
		read -a number <<< $$(git tag -l | grep -E "^$${component_dir}" | sort -Vr | head -n 1 | sed -E "s@^$${component_dir}/v([0-9]+)\.([0-9]+)\.([0-9]+)@\1 \2 \3@"); \
		commit_tag="$${component_dir}/v$$(($${number[0]}+1)).0.0"; \
		echo "tagging commit with $${commit_tag}" > /dev/stderr; \
		git tag "$${commit_tag}" -m "${TAG_MESSAGE}"; \
	)

bump-all-major-tags: check-branch check-tag-message $(component_major_tags)

########################################
############## SDK HELPERS #############
########################################

.PHONY: smithyctl/bin check-lib-url check-lib-version bump-go-dep bump-sdk-version

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

check-lib-url:
	@if [ -z "${LIB_URL}" ]; \
	then \
		echo >&2 "❌ Error: LIB_URL environment variable is an empty string"; \
		false; \
	fi

check-lib-version:
	@if [ -z "${LIB_VERSION}" ]; \
	then \
		echo >&2 "❌ Error: LIB_VERSION environment variable is an empty string"; \
		false; \
	fi

$(go_dep_update): check-lib-url check-lib-version
	@if $$(grep "${LIB_URL}" $$(dirname $@)/go.mod > /dev/null); \
	then \
		cd $$(dirname $@); \
		go get ${LIB_URL}@${LIB_VERSION}; \
		go mod tidy; \
		go mod vendor; \
		echo "✅ updating $$(dirname $@) dependency ${LIB_URL} to ${LIB_VERSION}"; \
	else \
		echo "⚠️ component $$(dirname $@) has no dependency on ${LIB_URL}"; \
	fi

# Bumps a specific dependency to a version for all components that use it
bump-go-dep: $(go_dep_update)
	@echo "✅✅ Finished updating ${LIB_URL} to version ${LIB_VERSION} everywhere"	

# Bumps the SDK dependencies to the latest version of the Smithy SDK based on the tags present in the repo
bump-sdk-version:
	$(MAKE) bump-go-dep LIB_VERSION=$$(git tag --list --sort="-version:refname" | grep sdk | head -n 1 | sed 's/sdk\///') LIB_URL="github.com/smithy-security/smithy/sdk"
	@echo "✅✅ Smithy Go SDK version update complete"

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
