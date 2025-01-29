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
NOT_VENDOR_PATHS := $(shell echo $(VENDOR_DIRS) | awk '{for (i=1; i<=NF; i++) print "-not -path \""$$i"/*\""}' | tr '\n' ' ')
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

TEKTON_VERSION=0.44.0
TEKTON_DASHBOARD_VERSION=0.29.2
ARANGODB_VERSION=1.2.19
NGINX_INGRESS_VERSION=4.2.5
NGINX_INGRESS_NS=ingress-nginx
NAMESPACE=default
ES_NAMESPACE=elastic-system
ES_OPERATOR_VERSION=2.2.0
ES_VERSION=8.3.2
MONGODB_VERSION=13.3.0
PG_VERSION=11.9.8
SMITHY_NS=smithy
TEKTON_NS=tekton-pipelines
ARANGODB_NS=arangodb

DOCKER=docker
PROTOC=protoc
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

third_party/tektoncd/swagger-v$(TEKTON_VERSION).json:
	@wget "https://raw.githubusercontent.com/tektoncd/pipeline/v$(TEKTON_VERSION)/pkg/apis/pipeline/v1beta1/swagger.json" -O $@

components/base/openapi_schema.json: third_party/tektoncd/swagger-v$(TEKTON_VERSION).json
	@cp $< $@

$(go_protos): %.pb.go: %.proto
	$(PROTOC) --go_out=. --go_opt=paths=source_relative $<

protos: $(go_protos)

build: components protos
	@echo "done building"

$(component_containers_publish): %/publish: %/docker
	./scripts/publish_component_container.sh $@

publish-component-containers: $(component_containers_publish)

publish-containers: publish-component-containers smithyctl-image-publish

clean-protos:
	@find . $(NOT_VENDOR_PATHS) -name '*.pb.go' -delete

clean-migrations-compose:
	cd tests/migrations/ && docker compose rm --force

clean: clean-protos clean-migrations-compose

########################################
######### CODE QUALITY TARGETS #########
########################################
.PHONY: lint install-lint-tools tests go-tests fmt fmt-proto fmt-go install-go-fmt-tools migration-tests

lint:
# we need to redirect stderr to stdout because Github actions don't capture the stderr lolz
	@reviewdog -fail-level=any -diff="git diff origin/main" -filter-mode=added 2>&1

install-lint-tools:
	GOTOOLCHAIN=go1.23.2 go install honnef.co/go/tools/cmd/staticcheck@2024.1.1
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

migration-tests: cmd/smithyctl/bin
	cd tests/migrations/ && docker compose up --abort-on-container-exit --build --exit-code-from tester

test: go-tests migration-tests

install-go-fmt-tools:
	@go install github.com/bufbuild/buf/cmd/buf@v1.28.1
	@go install golang.org/x/tools/cmd/goimports@latest

fmt-go:
	echo "Tidying up Go files"
	$(shell find . -type f -name "*.go" -not -name "*.pb.*" $(NOT_VENDOR_PATHS) | xargs gofmt -w | uniq)
	@goimports -local $$(cat go.mod | grep -E "^module" | sed 's/module //') -w $$(find . -type f -name *.go -not -name "*.pb.*" $(NOT_VENDOR_PATHS) | xargs -n 1 dirname | uniq)

install-md-fmt-tools:
	@npm ci

fmt-md:
	@echo "Tidying up MD files"
	@npm run format

fmt: fmt-go fmt-proto fmt-md

########################################
########## DEBUGGING TARGETS ###########
########################################

print-%:
	@echo $($*)

########################################
########## DEPLOYMENT TARGETS ##########
########################################
.PHONY: deploy-nginx deploy-arangodb-crds deploy-arangodb-operator add-es-helm-repo deploy-elasticoperator \
		tektoncd-dashboard-helm deploy-tektoncd-dashboard add-bitnami-repo dev-smithy dev-deploy dev-teardown \
		install install-oss-components deploy-cluster

deploy-nginx:
	@helm upgrade nginx-ingress https://github.com/kubernetes/ingress-nginx/releases/download/helm-chart-$(NGINX_INGRESS_VERSION)/ingress-nginx-$(NGINX_INGRESS_VERSION).tgz \
		--install \
		--namespace $(NGINX_INGRESS_NS) \
		--create-namespace \
		--set "controller.admissionWebhooks.enabled=false"

deploy-arangodb-crds:
	@helm upgrade arangodb-crds https://github.com/arangodb/kube-arangodb/releases/download/$(ARANGODB_VERSION)/kube-arangodb-crd-$(ARANGODB_VERSION).tgz \
		--install

deploy-arangodb-operator:
	@helm install --generate-name https://github.com/arangodb/kube-arangodb/releases/download/1.2.40/kube-arangodb-1.2.40.tgz

add-es-helm-repo:
	@helm repo add elastic https://helm.elastic.co
	@helm repo update

deploy-elasticoperator: add-es-helm-repo
	@helm upgrade elastic-operator elastic/eck-operator \
		--install \
		--namespace $(ES_NAMESPACE) \
		--create-namespace \
		--version=$(ES_OPERATOR_VERSION)

deploy/tektoncd/pipeline/release-v$(TEKTON_VERSION).yaml:
	@wget "https://storage.googleapis.com/tekton-releases/pipeline/previous/v$(TEKTON_VERSION)/release.yaml" -O $@

tektoncd-pipeline-helm: deploy/tektoncd/pipeline/release-v$(TEKTON_VERSION).yaml
	./scripts/generate_tektoncd_pipeline_helm.sh $(TEKTON_VERSION)

deploy-tektoncd-pipeline: tektoncd-pipeline-helm
	@helm upgrade tektoncd ./deploy/tektoncd/pipeline \
		--install \
		--namespace $(TEKTON_NS) \
		--create-namespace

deploy/tektoncd/dashboard/release-v$(TEKTON_DASHBOARD_VERSION).yaml:
    @wget "https://github.com/tektoncd/dashboard/releases/download/v$(TEKTON_DASHBOARD_VERSION)/tekton-dashboard-release.yaml" -O $@

tektoncd-dashboard-helm: deploy/tektoncd/dashboard/release-v$(TEKTON_DASHBOARD_VERSION).yaml
	./scripts/generate_tektoncd_dashboard_helm.sh $(TEKTON_DASHBOARD_VERSION)

deploy-tektoncd-dashboard: tektoncd-dashboard-helm
	@helm upgrade tektoncd-dashboard ./deploy/tektoncd/dashboard \
		--install \
		--values ./deploy/tektoncd/dashboard/values.yaml \
		--namespace $(TEKTON_NS)

add-bitnami-repo:
	@helm repo add bitnami https://charts.bitnami.com/bitnami

deploy-cluster:
	@scripts/kind-with-registry.sh

install: deploy-cluster dev-infra deploy-elasticoperator deploy-arangodb-crds add-bitnami-repo
	@echo "fetching dependencies if needed"
	@helm dependency build ./deploy/smithy/chart

	@echo "deploying smithy"
	@helm upgrade smithy ./deploy/smithy/chart \
		--install \
		--values ./deploy/smithy/values/dev.yaml \
		--create-namespace \
		--set "image.registry=$(CONTAINER_REPO)" \
		--namespace $(SMITHY_NS) \
		--version $(SMITHY_VERSION) \
		--wait

	@echo "Applying migrations"
	@helm upgrade deduplication-db-migrations ./deploy/deduplication-db-migrations/chart \
		--install \
		--values ./deploy/deduplication-db-migrations/values/dev.yaml \
		--create-namespace \
		--set "image.registry=$(CONTAINER_REPO)" \
		--namespace $(SMITHY_NS) \
		--set "image.tag=$(SMITHY_VERSION)" \
		--wait

	@echo "Installing Components"
	# we are setting the container repo to it's own value so that we can override it from other make targets
	# e.g. when installing oss components from locally built components, we want to `make install` with CONTAINER_REPO being the kind-registry, and the package_url being the component tar.gz
	$(MAKE) install-oss-components CONTAINER_REPO=$(CONTAINER_REPO) SMITHY_OSS_COMPONENTS_PACKAGE_URL=$(SMITHY_OSS_COMPONENTS_PACKAGE_URL)

dev-deploy-oss-components:
	@echo "Deploying components in local smithy instance"
	$(MAKE) dev-build-oss-components CONTAINER_REPO=$(CONTAINER_REPO)
	$(MAKE) install-oss-components CONTAINER_REPO=$(CONTAINER_REPO) SMITHY_OSS_COMPONENTS_PACKAGE_URL=$(SMITHY_OSS_COMPONENTS_PACKAGE_URL)

install-oss-components:
	@helm upgrade $(SMITHY_OSS_COMPONENTS_NAME) \
		$(SMITHY_OSS_COMPONENTS_PACKAGE_URL) \
		--install \
		--create-namespace \
		--namespace $(SMITHY_NS) \
		--set image.registry=$(CONTAINER_REPO) \
		--values ./deploy/deduplication-db-migrations/values/dev.yaml
	@echo "Done! Bumped version to $(SMITHY_VERSION)"

dev-build-oss-components:
	@echo "Building open-source components for local smithy instance..."
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	$(eval CONTAINER_REPO:=localhost:5000/smithy-security/smithy)
	$(eval TMP_DIR:=tmp)

	@mkdir $(TMP_DIR)
	$(MAKE) cmd/smithyctl/bin
	$(MAKE) -j 16 publish-component-containers CONTAINER_REPO=$(CONTAINER_REPO)
	@docker run \
		--platform $(GOOS)/$(GOARCH) \
		-v ./components:/components \
		-v ./tmp:/tmp \
		$(CONTAINER_REPO)/smithyctl:$(SMITHY_VERSION) components package \
			--version $(SMITHY_VERSION) \
			--chart-version $(SMITHY_VERSION) \
			--name $(SMITHY_OSS_COMPONENTS_NAME) \
			./components
	@rm -r $(TMP_DIR)

dev-smithy:
	$(eval GOOS:=linux)
	$(eval GOARCH:=amd64)
	$(eval CONTAINER_REPO:=localhost:5000/smithy-security/smithy)
	$(eval SMITHY_OSS_COMPONENTS_PACKAGE_URL:=./$(SMITHY_OSS_COMPONENTS_NAME)-$(SMITHY_VERSION).tgz)
	$(eval IN_CLUSTER_CONTAINER_REPO:=kind-registry:5000/smithy-security/smithy)

	$(MAKE) -j 16 smithyctl-image-publish CONTAINER_REPO=$(CONTAINER_REPO)
	$(MAKE) -j 16 dev-build-oss-components CONTAINER_REPO=$(CONTAINER_REPO)

	$(MAKE) install CONTAINER_REPO=$(IN_CLUSTER_CONTAINER_REPO) SMITHY_OSS_COMPONENTS_PACKAGE_URL=$(SMITHY_OSS_COMPONENTS_PACKAGE_URL)

dev-infra: deploy-nginx deploy-tektoncd-pipeline deploy-tektoncd-dashboard

dev-deploy: deploy-cluster dev-infra dev-smithy

dev-teardown:
	@kind delete clusters smithy-demo

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
