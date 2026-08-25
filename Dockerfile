FROM rust:1.95.0-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --locked --release -p tui-chat-server \
    && strip /build/target/release/tui-chat-server

FROM debian:bookworm-slim
# The official Rust builder already contains the CA bundle. Copy it instead
# of running apt-get in the runtime image; this keeps production builds
# independent of the Debian mirror and its mutable signing-key state.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN mkdir -p /data \
    && chown 65532:65532 /data
COPY --from=builder /build/target/release/tui-chat-server /usr/local/bin/tui-chat-server
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["tui-chat-server"]
CMD ["serve"]
