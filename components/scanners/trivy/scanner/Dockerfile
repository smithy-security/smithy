FROM  docker.io/aquasec/trivy:latest  

COPY ./entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/bin/bash", "-c", "/bin/entrypoint.sh" ]
