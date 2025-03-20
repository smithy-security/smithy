# Used only to build Go binaries.
FROM golang:1.23.3 AS builder

ARG SDK_VERSION=unset
WORKDIR /wrk

# Copy only go related files.
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd/git-clone ./cmd/git-clone
COPY pkg ./pkg
# And builder.
COPY Makefile .

# Install make
RUN apt-get update && \
    apt-get install -y make && \
    rm -rf /var/lib/apt/lists/*

RUN make build-target

# Used to actually run the binary in minimal image.
FROM gcr.io/distroless/base-debian12

COPY --from=builder /wrk/target /bin/target

# Setting the workdir where we'll clone repositories.
WORKDIR /

# Set the binary as the entry point
ENTRYPOINT ["/bin/target"]
