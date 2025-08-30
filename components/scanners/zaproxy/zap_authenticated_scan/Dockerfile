FROM zaproxy/zap-stable:latest

WORKDIR /workdir

USER root
RUN apt update && \
    apt remove -y python3-cachecontrol && \
    apt install -y python3-virtualenv python3-poetry

# zap has python so we can just copy a script here
COPY zap_authenticated_scan.py /workdir/zap_authenticated_scan.py
COPY requirements.txt /workdir/

RUN chown -R zap:zap /workdir

USER zap
ENV PYTHONNOUSERSITE=1
RUN chmod +x zap_authenticated_scan.py && \
    virtualenv venv && \
    . venv/bin/activate && \
    pip install -r requirements.txt


ENV HTTP_PROXY='http://localhost:8090'
ENV HTTPS_PROXY='http://localhost:8090'

ENTRYPOINT ["/workdir/venv/bin/python3", "/workdir/zap_authenticated_scan.py"]
