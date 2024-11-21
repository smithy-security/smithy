# Used only to build Go binaries.
FROM golang:1.23.3 AS builder

WORKDIR /wrk

# Copy only go related files.
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd/git-clone ./cmd
COPY pkg ./pkg

# Security hardening and building flags for minimal binaries.
#
# These CGO_CPPFLAGS help preventing overflows.
# Add a small overhead at compile time.
ENV CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2 -fstack-protector-all"
# Makes memory exploitation harder.
# Add a small overhead at compile time.
ENV GOFLAGS="-buildmode=pie"
ENV CGO_ENABLED=0
ENV GOOS="linux"
ENV GOARCH="amd64"
RUN go build -ldflags "-s -w" -trimpath -o app ./cmd/main.go

# Create a workspace to clone repos to.
RUN mkdir -p /workspace

# Used to actually run the binary in minimal image.
FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder --chown=65534:65534 /wrk/app /bin/app
COPY --from=builder --chown=65534:65534 /workspace /workspace

# Run as UID for 'nobody' since k8s pod securityContext runAsNonRoot can't resolve the user ID:
# https://github.com/kubernetes/kubernetes/issues/40958
USER 65534

# Setting the workdir where we'll clone repositories.
WORKDIR /workspace

# Set the binary as the entry point
ENTRYPOINT ["/bin/app"]
