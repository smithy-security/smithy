FROM golang:bookworm AS build

WORKDIR /application
COPY . /application/

RUN go build -o /application/mosf-orchestrator /application/cmd/main.go

FROM opensecurity/mobile-security-framework-mobsf:v4.3.2

COPY --from=build /application/mosf-orchestrator /usr/local/bin/mosf-orchestrator

ENTRYPOINT ["/usr/local/bin/mosf-orchestrator"]
