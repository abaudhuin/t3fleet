FROM rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin t3fleet-server --bin t3fleet

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /data --create-home t3fleet
COPY --from=builder /src/target/release/t3fleet-server /usr/local/bin/t3fleet-server
COPY --from=builder /src/target/release/t3fleet /usr/local/bin/t3fleet
USER t3fleet
WORKDIR /data
ENV T3FLEET_LISTEN=0.0.0.0:8080
ENV T3FLEET_DB=/data/t3fleet.db
EXPOSE 8080
ENTRYPOINT ["t3fleet-server"]
