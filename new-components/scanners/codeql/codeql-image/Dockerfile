FROM golang:1.23-bookworm AS build

WORKDIR /build

COPY . /build/
RUN go build -o codeql-runner main.go

WORKDIR /
RUN apt update &&\
    apt install -y wget jq &&\
    wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.20.4/codeql-bundle-linux64.tar.gz &&\
    ls -lah &&\
    tar zxvf codeql-bundle-linux64.tar.gz

ENV CODEQL_ALLOW_INSTALLATION_ANYWHERE=true
ENTRYPOINT ["/build/codeql-runner"]
