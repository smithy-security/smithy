FROM golang:latest

WORKDIR /playwright
RUN go mod init github.com/smithy-security/pdf-consumer && \
        go get -u github.com/playwright-community/playwright-go && \
        go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps

ENV PATH="${PATH}:/go/pkg/mod/github.com/playwright-community"
COPY components/consumers/pdf/pdf /playwright/pdf
COPY components/consumers/pdf/default.html /playwright/default.html
ENTRYPOINT ["/playwright/pdf"]
