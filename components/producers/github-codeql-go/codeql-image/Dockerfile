FROM golang:1.22-bookworm

WORKDIR /

RUN apt update &&\
    apt install wget &&\
    wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.20.4/codeql-bundle-linux64.tar.gz &&\
    ls -lah &&\
    tar zxvf codeql-bundle-linux64.tar.gz &&\
    ls -lah  && pwd

ENTRYPOINT ["/codeql/codeql"]
