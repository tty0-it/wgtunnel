FROM alpine:latest

ARG WGTUNNEL_VERSION
LABEL \
	org.opencontainers.image.title="wgtunnel" \
	org.opencontainers.image.description="Simple HTTP tunnel over WireGuard." \
	org.opencontainers.image.url="https://github.com/tty0-it/wgtunnel" \
	org.opencontainers.image.source="https://github.com/tty0-it/wgtunnel" \
	org.opencontainers.image.version="$WGTUNNEL_VERSION"

RUN adduser -D -u 1000 tunneld
USER tunneld

COPY tunneld /
COPY tunnel /

CMD ["/tunneld"]
