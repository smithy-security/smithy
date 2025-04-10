FROM zaproxy/zap-stable:latest

# zap has python so we can just copy a script here
COPY zap-authenticated-scan.py /workdir/zap-authenticated-scan.py
COPY requirements.txt /workdir/requirements.txt
WORKDIR /workdir

USER root
RUN apt update && \
    apt install -y python3-virtualenv && \
    chown -R zap:zap /workdir

USER zap

RUN virtualenv venv && \
    . venv/bin/activate && \
    pip install -r requirements.txt && \
    chmod +x zap-authenticated-scan.py

ENV HTTP_PROXY='http://localhost:8090'
ENV HTTPS_PROXY='http://localhost:8090'
ENTRYPOINT ["./venv/bin/python3", "/workdir/zap-authenticated-scan.py" ]
