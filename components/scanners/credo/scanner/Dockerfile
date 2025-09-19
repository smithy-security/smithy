FROM elixir:otp-28

COPY entrypoint.sh /entrypoint.sh

# Install a specific version of the Credo escript (e.g., 1.7.12)
RUN mix escript.install hex credo@1.7.12 --force && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
