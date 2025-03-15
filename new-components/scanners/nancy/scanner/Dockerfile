FROM docker.io/sonatypecommunity/nancy:latest AS nancy
FROM golang:1.20

COPY --from=nancy /nancy /nancy
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
