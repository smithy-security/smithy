FROM elixir:otp-28

# Install jq
RUN apt-get update && apt-get install -y jq

COPY entrypoint.sh /entrypoint.sh
# Install Credo
RUN mix escript.install hex credo 1.7.12 --force && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]