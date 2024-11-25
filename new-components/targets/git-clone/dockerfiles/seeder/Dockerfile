# Used only to build Go binaries.
FROM golang:1.23.3 AS builder

WORKDIR /wrk

# Copy only go related files.
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd/seeder ./cmd

RUN go build -trimpath -o app ./cmd/main.go

# Used to actually run the binary in minimal image.
FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder --chown=65534:65534 /wrk/app /bin/app

# Set the binary as the entry point
ENTRYPOINT ["/bin/app"]
