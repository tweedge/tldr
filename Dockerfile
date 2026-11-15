# syntax=docker/dockerfile:1

FROM rust:1.88-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
COPY examples ./examples

# Build only the binary; examples and tests are not needed in the image.
RUN cargo build --release --locked --bin tldr

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin tldr \
    && mkdir -p /data /config \
    && chown -R tldr:tldr /data /config

COPY --from=builder /build/target/release/tldr /usr/local/bin/tldr

LABEL org.opencontainers.image.title="tldr" \
      org.opencontainers.image.description="Historical DNS zone-transfer archive" \
      org.opencontainers.image.source="https://github.com/tweedge/tldr"

WORKDIR /data
USER tldr

ENTRYPOINT ["tldr"]
CMD ["--daemon", "--config", "/config/config.toml"]
