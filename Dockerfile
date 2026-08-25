ARG RUST_BASE=rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
ARG RUNTIME_BASE=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

FROM ${RUST_BASE} AS builder
WORKDIR /build
COPY . .
# Use rsproxy for Rust toolchain and crates.io traffic in restricted networks.
# Every value remains a build argument so deployments can override the mirror.
ARG RUSTUP_DIST_SERVER=https://rsproxy.cn
ARG RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup/rustup
ENV RUSTUP_DIST_SERVER=${RUSTUP_DIST_SERVER} \
    RUSTUP_UPDATE_ROOT=${RUSTUP_UPDATE_ROOT}
COPY docker/cargo-rsproxy.toml /usr/local/cargo/config.toml
RUN case "$(uname -m)" in \
        x86_64) host_toolchain="1.95.0-x86_64-unknown-linux-gnu" ;; \
        aarch64) host_toolchain="1.95.0-aarch64-unknown-linux-gnu" ;; \
        *) echo "unsupported build architecture: $(uname -m)" >&2; exit 1 ;; \
    esac \
    && cargo "+${host_toolchain}" build --locked --release -p tui-chat-server \
    && strip /build/target/release/tui-chat-server

FROM ${RUNTIME_BASE}
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
