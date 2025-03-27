FROM zaproxy/zap-stable:latest


# zap has python so we can just copy a script here
COPY zap-authenticated-scan.py /workdir/zap-authenticated-scan.py
COPY requirements.txt /workdir/requirements.txt
COPY entrypoint.sh /workdir/entrypoint.sh
WORKDIR /workdir

USER root
RUN apt update && \
    apt install -y python3-virtualenv && \
    chown -R zap:zap /workdir

USER zap

RUN virtualenv venv && \
    . venv/bin/activate && \
    pip install -r requirements.txt && \
    chmod +x entrypoint.sh

ENTRYPOINT [ "/workdir/entrypoint.sh" ]
