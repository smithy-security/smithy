FROM docker.io/aquasec/trivy:0.65.0

COPY ./entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/bin/bash", "-c", "/bin/entrypoint.sh" ]
