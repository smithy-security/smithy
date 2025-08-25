FROM elixir:otp-28

COPY entrypoint.sh /entrypoint.sh
# Install Sobelow
RUN echo Y |mix escript.install github sobelow/sobelow  && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
