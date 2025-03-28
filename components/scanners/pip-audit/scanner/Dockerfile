FROM python:bookworm 

COPY ./entrypoint.sh /entrypoint.sh
RUN pip install pip-audit &&\
    chmod +x /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
