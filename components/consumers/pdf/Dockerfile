FROM golang:1.22-bookworm

ARG EXECUTABLE_SRC_PATH
ARG EXECUTABLE_TARGET_PATH
ENV EXECUTABLE_TARGET_PATH=${EXECUTABLE_TARGET_PATH}
COPY ${EXECUTABLE_SRC_PATH} /app/${EXECUTABLE_TARGET_PATH}

# Install playwright cli with right version for later use
RUN go install github.com/playwright-community/playwright-go/cmd/playwright@v0.4702.0 && \
    apt-get update && apt-get install -y ca-certificates tzdata &&\
    playwright install chromium --with-deps &&\
    ln -s /app/${EXECUTABLE_TARGET_PATH} /bin/component


COPY components/consumers/pdf/default.html /app/components/consumers/pdf/default.html
WORKDIR /app/components/consumers/pdf
ENTRYPOINT ["/app/components/consumers/pdf/pdf"]
