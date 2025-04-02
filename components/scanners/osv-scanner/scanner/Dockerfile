FROM golang:1.24 AS builder 

COPY ./entrypoint.sh /entrypoint.sh
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest &&\
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
