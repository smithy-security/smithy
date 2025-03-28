FROM golang:1.23.3 AS builder
COPY . /workdir
WORKDIR /workdir
# Install Playwright CLI with the correct version
RUN go install github.com/playwright-community/playwright-go/cmd/playwright@v0.4901.0
# Build your Go application
RUN GOOS=linux GOARCH=amd64 go build -o /bin/reporter cmd/main.go

# Stage 3: Final image
FROM ubuntu:22.04

COPY --from=builder /bin/reporter /
COPY --from=builder /go/ /go/

RUN apt-get update
RUN apt-get install -y ca-certificates tzdata
RUN ./go/bin/playwright install chromium --with-deps
RUN rm -rf /var/lib/apt/lists/*

CMD ["/reporter"]
