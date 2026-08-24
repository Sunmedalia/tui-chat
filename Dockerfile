FROM rust:1.95.0-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --locked --release -p tui-chat-server \
    && strip /build/target/release/tui-chat-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data \
    && chown 65532:65532 /data
COPY --from=builder /build/target/release/tui-chat-server /usr/local/bin/tui-chat-server
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["tui-chat-server"]
CMD ["serve"]
