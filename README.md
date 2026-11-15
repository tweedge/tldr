# tldr

*A continuously updated historical DNS zone-transfer archive.*

TLDR periodically attempts [DNS zone transfers (AXFR)](https://en.wikipedia.org/wiki/DNS_zone_transfer)
against the [root nameservers](https://en.wikipedia.org/wiki/Root_name_server) and
every TLD, archives the resulting zones, and alerts on *significant* changes.
It is a Rust rewrite of the original Python `scan.py`, adding compression,
deduplication, 30-day retention, and noise-filtered Pushover notifications.

This is classic TLDR AXFR only; zone walks are intentionally out of scope.

## What it does

- **Discovers** the current TLD list from IANA and resolves authoritative
  nameservers with DNS-over-HTTPS (so discovery works even where port 53 is
  filtered).
- **Transfers** each root/TLD zone over TCP port 53, directly or through a
  SOCKS5 proxy.
- **Archives** every successful transfer into a content-addressed, zstd-
  compressed store with a JSON manifest and per-day summaries. Identical zones
  deduplicate to a single blob; 30 days are retained by default.
- **Diffs** each zone against its previous snapshot semantically — ignoring SOA
  serials, DNSSEC signature rotation, NSEC re-derivation, and TTL wobble — and
  rates the change `none`/`low`/`medium`/`high`.
- **Notifies** via Pushover for changes at or above a configurable floor
  (default: `high`, i.e. new zones, apex nameserver changes, and mass delegation
  churn).

## Architecture

```
src/                  tldr binary: CLI, config, scan orchestration, notifications
crates/tldr-core/     library: zone model, AXFR client, archive, diff, discovery
examples/legacy_report.rs   compare the 2022 dig archive against the new one
archives/             the legacy (2022) archive, reference only
```

Key design choices:

- **hickory-proto** for DNS wire encoding/decoding and record types.
- **hickory-resolver** with DoH for all discovery (never port 53).
- A hand-rolled AXFR client because port 53 may be intercepted; it supports a
  SOCKS5 transport for a clean-egress path.
- **zstd** content-addressed blobs + SHA-256, so re-transfers of unchanged
  zones cost nothing on disk.

## Configuration

See `config.toml`. The important knobs:

```toml
[archive]
path = "/data/archive"
retention_days = 30

[scan]
concurrency = 12
timeout_secs = 20
# socks5_proxy = "127.0.0.1:1080"   # for networks that filter port 53
transport = "auto"

[diff]
notify_floor = "high"                # none | low | medium | high

[notify]
enabled = true
# credentials are read from the environment:
#   PUSHOVER_APP_TOKEN, PUSHOVER_USER_TOKEN
```

## Usage

```sh
tldr --config config.toml --once            # one cycle
tldr --config config.toml --daemon          # every 3 hours
tldr --config config.toml --dry-run         # discovery only
tldr --config config.toml --once --json     # machine-readable report
```

## Docker

```sh
docker build -t tldr .
docker compose up -d        # uses ./config.toml and ./data
```

The archive lives under the mounted `/data` directory and is append-only
except for retention pruning.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

See `AGENTS.md` for environment gotchas (port 53 interception is the big one)
and the noise policy.

## Credits

Originally a fork of [mandatoryprogrammer/TLDR](https://github.com/mandatoryprogrammer/TLDR)
by way of [tweedge/tldr](https://github.com/tweedge/tldr). See also
[monoidic/TLDR2](https://github.com/monoidic/TLDR2) and
[flotwig/TLDR-2](https://github.com/flotwig/TLDR-2) for prior art.
