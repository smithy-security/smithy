FROM golang:1.23-bookworm AS build

WORKDIR /build

COPY . /build/
RUN go build -o cdxgen-atom-runner main.go

FROM ghcr.io/appthreat/atom:v2.1.14 AS run
COPY --from=build /build/cdxgen-atom-runner /runner
ENTRYPOINT ["/runner"]
