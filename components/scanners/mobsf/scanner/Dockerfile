FROM golang:bookworm AS build

WORKDIR /application
COPY . /application/

RUN go build -o /application/mobsf-orchestrator /application/cmd/main.go

FROM opensecurity/mobile-security-framework-mobsf:v4.3.2

COPY --from=build /application/mobsf-orchestrator /usr/local/bin/mobsf-orchestrator

ENTRYPOINT ["/usr/local/bin/mobsf-orchestrator"]
