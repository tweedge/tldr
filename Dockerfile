# syntax=docker/dockerfile:1

# Build a fully static (musl) binary, then ship it in a scratch image: no OS,
# no shell, no libc, nothing to patch. TLS trust comes from the webpki-roots
# crate compiled into the binary, so no ca-certificates are needed at runtime.
FROM --platform=$TARGETPLATFORM rust:1.89-alpine AS builder

ARG VERSION=dev

RUN apk add --no-cache musl-dev build-base
WORKDIR /build

COPY Cargo.toml Cargo.lock build.rs ./
COPY crates ./crates
COPY src ./src

# Build natively on Alpine (its host target is musl), so the output is already
# a static musl binary. buildx runs this under QEMU for non-native arches, so
# no cross C compiler is needed.
RUN TLDR_VERSION_OVERRIDE="$VERSION" cargo build --release --locked --bin tldr \
    && cp target/release/tldr /tldr \
    && mkdir -p /empty/data && chown 10001:10001 /empty/data

FROM scratch

COPY --from=builder /tldr /usr/local/bin/tldr
# Seed /data with the runtime user's ownership so a fresh named volume inherits
# it; a host bind mount must be writable by uid 10001 on the host.
COPY --from=builder --chown=10001:10001 /empty/data /data

# Unprivileged runtime. Numeric uid/gid work without /etc/passwd in scratch.
USER 10001:10001

ENV RUST_LOG=info
WORKDIR /data

# The archive lives on a mounted volume (compressed, deduplicated, 30-day
# retention by default). Config is mounted read-only, e.g.:
#   docker run -v ./config.toml:/config/config.toml:ro -v ./data:/data \
#     ghcr.io/tweedge/tldr:latest
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/tldr"]
CMD ["--daemon", "--config", "/config/config.toml"]
