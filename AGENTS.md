# AGENTS.md

Orientation for AI agents and contributors working on TLDR.

## What this project is

TLDR periodically performs DNS zone transfers (AXFR) against the root zone and
every TLD, archives the resulting zones, and reports *semantic* changes. It is a
Rust rewrite of the original Python `scan.py` (last run circa 2022) that adds
compression/deduplication, 30-day retention, and significance-filtered Pushover
alerts. Zone walks are intentionally out of scope; this is classic TLDR AXFR
only.

## Layout

- `src/` — the `tldr` binary: CLI (`main.rs`), config (`config.rs`), run
  orchestration (`scan.rs`), notifications (`notify.rs`).
- `crates/tldr-core/` — library with the reusable pieces:
  - `zone.rs` — canonical zone model, text (de)serialization, SHA-256 digest.
  - `axfr.rs` — AXFR client (direct TCP or SOCKS5), connection to port 53.
  - `archive.rs` — content-addressed zstd blob store, manifest, retention.
  - `diff.rs` — semantic diff + `Significance` classification.
  - `discovery.rs` — IANA TLD list and DoH-based NS/address resolution.
- `examples/legacy_report.rs` — compares the old `archives/` dig dump against
  the new archive.
- `archives/` — the legacy (2022) archive, kept for reference only.
- `config.toml` — example/default configuration.

## Conventions

- Rust 2021, `rust-version = 1.88`. Run `cargo fmt` and
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- No comments that restate the code; only explain non-obvious intent. Doc
  comments on public items are expected.
- Unit tests live beside the code (`#[cfg(test)]`); end-to-end pipeline tests
  live in `tests/`.
- The archive format is a public contract: `manifest.json` plus
  `blobs/<2>/<62>.zst` and `daily/<date>/zones.json`. Changing it requires
  updating this file.

## Environment gotchas (important)

**Port 53 is untrustworthy on many networks.** This development LAN — and
`whisper.lan`, the deploy target — transparently intercepts all TCP/UDP 53
traffic and answers with an injected `REFUSED` for AXFR. The result is a
silent, total failure of zone transfers even though individual DNS lookups
appear to work. This is why:

- NS/address discovery uses **DNS-over-HTTPS** (port 443), never port 53.
- AXFR supports a **SOCKS5 proxy** (`scan.socks5_proxy`), typically an
  `ssh -N -D 1080 user@clean-egress-host` dynamic forward. A host with
  unfiltered egress is required for successful transfers.

Before concluding "that zone is not transferable", check whether AXFR works
from a clean-egress host. Known-good reference: `arpa.`, `fj.`, `gp.`, `mw.`,
`er.`, `xn--ygbi2ammx.`, and the root zone all transferred successfully through
a clean egress path.

## Commands

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo run -- --config config.toml --dry-run            # discovery only
cargo run -- --config config.toml --once --json        # one cycle
cargo run -- --config config.toml --daemon             # continuous
cargo run --example legacy_report -- archives <new-archive>
```

## Deployment

Built as a container (see `Dockerfile`, `compose.yaml`) and deployed to
`whisper.lan` with `/data` mounted for the archive. The archive is safe to
back up by copying the mounted directory; it is append-only except for
retention pruning.

## Noise policy

Notifications are driven by `diff::Significance`, not raw record counts. By
default only `high` changes notify: new zones, apex NS changes, or mass
delegation churn. SOA serial increments, DNSSEC signature rotation, NSEC
re-derivation, and glue TTL wobble are deliberately classified as `none` and
never page. Tune with `[diff]` in config, not by lowering the floor to `low`.
