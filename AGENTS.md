# AGENTS.md

Orientation for AI agents and contributors working on TLDR.

## What this project is

TLDR periodically performs DNS zone transfers (AXFR) against the root zone and every TLD, archives the resulting zones, and reports *semantic* changes. It is a Rust rewrite of the original Python `scan.py` (last run circa 2022) that adds compression/deduplication, 30-day retention, and significance-filtered Pushover alerts. Zone walks are intentionally out of scope; this is classic TLDR AXFR only.

## Layout

- `src/` — the `tldr` binary: CLI (`main.rs`), config (`config.rs`), run orchestration (`scan.rs`), notifications (`notify.rs`), dead-man's-switch heartbeat/health check (`health.rs`).
- `crates/tldr-core/` — library with the reusable pieces:
  - `zone.rs` — canonical zone model, text (de)serialization, SHA-256 digest.
  - `axfr.rs` — AXFR client over direct TCP port 53.
  - `archive.rs` — content-addressed zstd blob store, manifest, retention.
  - `diff.rs` — semantic diff + `Significance` classification.
  - `discovery.rs` — IANA TLD list and DoH-based NS/address resolution.
- `config.toml` — example/default configuration.

## Conventions

- Rust 2021, `rust-version = 1.89`. Prefer the grugbrain approach: small, flat, obvious code over clever abstraction. Run `cargo fmt` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- No comments that restate the code; only explain non-obvious intent. Doc comments on public items are expected.
- Unit tests live beside the code (`#[cfg(test)]`); end-to-end pipeline tests live in `tests/`.
- The archive format is a public contract: `manifest.json`, `heartbeat.json`, `blobs/<2>/<62>.zst` and `daily/<date>/zones.json`. Manifest and heartbeat writes are atomic (temp file + rename). Changing the format requires updating this file.

## Environment gotcha (important): deploy on unfiltered DNS

**TLDR must run on a network with a clean path to port 53.** Many networks (including the development LAN) transparently intercept all TCP/UDP 53 traffic and answer AXFR with an injected `REFUSED`. Zone transfers then fail silently and look like "this zone is not transferable", even though plain lookups work.

- Discovery is immune: NS/address resolution uses **DNS-over-HTTPS** (port 443).
- AXFR is not: it must reach authoritative servers on **TCP 53** directly. There is no in-process proxy or workaround; deploy on a host with unfiltered egress (the current target is `cybersecurity.theater`).

Before concluding "that zone is not transferable", confirm AXFR works from the deployment host. Known-good reference zones: `arpa.`, `fj.`, `mw.`, `er.`, `xn--ygbi2ammx.`, and the root zone.

## Commands

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo run -- --config config.toml --dry-run            # discovery only
cargo run -- --config config.toml --once --json        # one cycle
cargo run -- --config config.toml --daemon             # continuous (hourly)
cargo run -- --config config.toml --test-notification   # verify Pushover
cargo run -- --config config.toml --check-health        # dead-man's-switch check
bash scripts/build-release.sh                           # static Linux artifacts in dist/
```

Releases: push a `vX.Y.Z` tag and `.github/workflows/release.yml` builds the
static musl binaries (amd64/arm64/arm/386) and publishes a GitHub release; the
image publishes to GHCR. The binary is fully static (musl) so the `Dockerfile`
can ship it in a `scratch` image — keep it that way (no glibc-only deps, no C
TLS providers; `aws-lc-rs` is deliberately excluded via the ring-only pin in
`Cargo.toml`). TLS trust comes from `webpki-roots`, not system certs.

## Deployment

Deployed to `cybersecurity.theater` (aarch64, no Docker) as a systemd user service; see `deploy/`. A `Dockerfile` and `compose.yaml` are provided for hosts that prefer containers. The archive directory is append-only except for retention pruning, so it is safe to back up by copying it.

## Watchdog (dead-man's switch)

TLDR only reports on *changes*, so a dead or quietly-broken run looks like silence. `health.rs` fixes that: every completed cycle writes `heartbeat.json` beside the archive, and `tldr --check-health` (run by `deploy/tldr-health.timer` every 30 min) sends a high-priority Pushover alert and exits 75 if the heartbeat is older than `[health] max_age` (default 3h). A cycle that has never run leaves no heartbeat, which also alerts. Do not add a second overlapping alerting path; keep the single heartbeat check.

## Noise policy

Notifications are driven by `diff::Significance`, not raw record counts. By default only `high` changes notify: new zones, apex NS changes, or mass delegation churn. SOA serial increments, DNSSEC signature rotation, NSEC re-derivation, and glue TTL wobble are deliberately classified as `none` and never page. Tune with `[diff]` in config, not by lowering the floor to `low`.
