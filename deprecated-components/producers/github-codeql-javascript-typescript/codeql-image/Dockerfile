FROM node:23.8-bookworm-slim

WORKDIR /

RUN apt update &&\
    apt install -y wget &&\
    wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.20.4/codeql-bundle-linux64.tar.gz &&\
    ls -lah &&\
    tar zxvf codeql-bundle-linux64.tar.gz &&\
    ls -lah  && pwd

ENTRYPOINT ["/codeql/codeql"]
