FROM elixir:otp-28

# Install jq
RUN apt-get update && apt-get install -y jq

COPY entrypoint.sh /entrypoint.sh
# Install Sobelow
RUN mix escript.install github sobelow/sobelow tag v0.14.0 --force && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
