.PHONY: run run-with-seeder shutdown build-target

BUILD_ARCHITECTURE=
COMPONENT_REGISTRY=localhost:5000
COMPONENT_REPOSITORY=smithy-security/smithy/components/targets/git-clone
COMPONENT_TAG=latest

run:
	docker-compose up --build --force-recreate --remove-orphans gitea target

run-with-seeder:
	docker-compose up --build --force-recreate --remove-orphans

shutdown:
	docker-compose down --rmi all

build-target:
	# Security hardening and building flags for minimal binaries.
    #
    # These CGO_CPPFLAGS help preventing overflows.
    # Add a small overhead at compile time.
	CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2 -fstack-protector-all" \
	# Makes memory exploitation harder.
    # Add a small overhead at compile time.
	GOFLAGS="-buildmode=pie" \
	GOOS="linux" \
	GOARCH="amd64" \
		go build -ldflags "-s -w" -trimpath -o target ./cmd/git-clone/main.go

image:
	docker build $$([ "${BUILD_ARCHITECTURE}" != "" ] && echo "--platform=${BUILD_ARCHITECTURE}" ) \
				 --tag $(COMPONENT_REGISTRY)/$(COMPONENT_REPOSITORY):$(COMPONENT_TAG) \
				 --file dockerfiles/git-clone/Dockerfile .
