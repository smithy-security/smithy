FROM elixir:otp-28

COPY entrypoint.sh /entrypoint.sh
# Install Sobelow
RUN echo Y |mix escript.install github sobelow/sobelow tag v0.14.0 && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
