FROM golang:bookworm AS build

COPY . /code

WORKDIR /code
RUN go mod tidy &&\
    go mod vendor &&\
    go build cmd/main.go

FROM scratch AS run

COPY --from=build /code/main /main

 ENTRYPOINT [ "/main" ]

