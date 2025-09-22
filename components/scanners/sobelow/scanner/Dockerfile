FROM elixir:otp-28

COPY entrypoint.sh /entrypoint.sh
# Install Sobelow
RUN mix escript.install github sobelow/sobelow tag v0.14.0 --force && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
