FROM debian:bookworm-slim

RUN apt update &&\
    apt install -y skopeo

COPY ./entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh"]
