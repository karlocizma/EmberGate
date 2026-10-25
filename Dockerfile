FROM rust:1-trixie AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev cmake clang && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pingora ./pingora
COPY gateway ./gateway
COPY docs ./docs
RUN cargo build --locked --release --manifest-path gateway/Cargo.toml

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3t64 ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home gateway && mkdir /data /var/log/embergate && chown gateway:gateway /data /var/log/embergate
COPY --from=builder /build/gateway/target/release/embergate /build/gateway/target/release/embergate-cli /usr/local/bin/
USER gateway
ENV GATEWAY_DATA_DIR=/data GATEWAY_PROXY_ADDR=0.0.0.0:8080 GATEWAY_ADMIN_ADDR=0.0.0.0:9090
EXPOSE 8080 8443 9090
ENTRYPOINT ["embergate"]
