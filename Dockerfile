FROM alpine:3.19

ARG ARCH

COPY --chown=root:root /target/${ARCH}-unknown-linux-musl/debug/dnstop /app/

ENV RUST_LOG=info

EXPOSE 8080
CMD ["/app/dnstop"]