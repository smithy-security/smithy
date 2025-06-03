FROM golang:1.24-bookworm AS build

WORKDIR /build

COPY . /build/
RUN go build -o codeql-runner main.go

WORKDIR /
RUN apt update &&\
    apt install -y wget jq &&\
    wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.20.4/codeql-bundle-linux64.tar.gz &&\
    ls -lah &&\
    tar zxvf codeql-bundle-linux64.tar.gz

# Install Node.js
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash && \
/bin/bash -c 'source "$HOME/.nvm/nvm.sh" && nvm install node && node -v'


ENV CODEQL_ALLOW_INSTALLATION_ANYWHERE=true
ENTRYPOINT ["/build/codeql-runner"]
