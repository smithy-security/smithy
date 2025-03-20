# Used only to build Go binaries.
FROM golang:1.23.3 AS builder

ARG COMPONENT_PATH=.
ARG COMPONENT_BINARY_SOURCE_PATH=cmd/main.go

WORKDIR /wrk

# Copy only go related files.
COPY ${COMPONENT_PATH} ./

# Security hardening and building flags for minimal binaries.
#
# These CGO_CPPFLAGS help preventing overflows.
# Add a small overhead at compile time.
RUN CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2 -fstack-protector-all" \
    # Makes memory exploitation harder.
    # Add a small overhead at compile time.
    GOFLAGS="-buildmode=pie" \
      go build \
        -ldflags "-X github.com/smithy-security/smithy/sdk.Version=${SDK_VERSION} -s -w" \
        -trimpath \
        -o \
        app \
        ${COMPONENT_BINARY_SOURCE_PATH}

# Create a workspace to clone repos to.
RUN mkdir -p /workspace

# Used to actually run the binary in minimal image.
FROM gcr.io/distroless/base-debian12

COPY --from=builder /wrk/app /bin/app

# Setting the workdir where we'll clone repositories.
WORKDIR /workspace

# Set the binary as the entry point
ENTRYPOINT ["/bin/app"]
