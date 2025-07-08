FROM elixir:otp-28

COPY entrypoint.sh /entrypoint.sh
# Install Credo
RUN echo Y |mix escript.install hex credo  && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
