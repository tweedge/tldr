# Deploying TLDR

## Requirement: a network without DNS filtering

**TLDR must run on a host with a clean, unfiltered path to TCP/UDP port 53.** Many consumer, campus, and enterprise networks transparently intercept all port-53 traffic and answer with a locally injected `REFUSED` for AXFR. When that happens every zone looks untransferable even though the transfer never reached the authoritative server, and there is no reliable in-process workaround.

Discovery is unaffected (it uses DNS-over-HTTPS on port 443), so a filtered host will find zones and nameservers but fail every transfer. Deploy TLDR on a host whose port 53 reaches the public internet directly — the deployment target here is **`cybersecurity.theater`**, which has a clean egress.

If you are unsure whether a host is filtered, compare AXFR results against a known-good zone (`arpa.`, `fj.`, `mw.`, `er.`, or the root). If those fail while ordinary lookups succeed, the network is intercepting DNS.

## Target host

`cybersecurity.theater` is aarch64 Ubuntu with no Docker and no Rust toolchain. The binary is built natively on the host with rustup (user-local, no sudo), then installed as a systemd **user** service with lingering enabled so it survives logout.

## Deploy

```sh
# 1. Build on the target (native, no cross-compilation needed).
scp -r Cargo.toml Cargo.lock crates src ubuntu@cybersecurity.theater:~/tldr-src/
ssh ubuntu@cybersecurity.theater '
  curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal &&
  ~/.cargo/bin/cargo build --release --locked --manifest-path ~/tldr-src/Cargo.toml
'

# 2. Install the binary, config, units and credential file.
ssh ubuntu@cybersecurity.theater '
  mkdir -p ~/tldr-deploy/data ~/.config/systemd/user && chmod 700 ~/tldr-deploy &&
  cp ~/tldr-src/target/release/tldr ~/tldr-deploy/tldr &&
  chmod 600 ~/tldr-deploy/tldr.env 2>/dev/null || true
'
scp deploy/config.toml ubuntu@cybersecurity.theater:~/tldr-deploy/config.toml
scp deploy/tldr.service deploy/tldr-health.service deploy/tldr-health.timer \
    ubuntu@cybersecurity.theater:~/.config/systemd/user/

# 3. Enable the scan service and the health timer. Linger keeps user services
#    running without a login session.
ssh ubuntu@cybersecurity.theater '
  loginctl enable-linger ubuntu &&
  systemctl --user daemon-reload &&
  systemctl --user enable --now tldr.service &&
  systemctl --user enable --now tldr-health.timer
'
```

## Credentials

```
# ~/tldr-deploy/tldr.env  (mode 600, never committed)
PUSHOVER_APP_TOKEN=...
PUSHOVER_USER_TOKEN=...
```

If the tokens are unset, TLDR logs a warning and skips alerts; scanning and archiving continue normally.

## Will I be alerted if TLDR stops working?

Normally you are only paged when something *changes*, so a dead or broken TLDR looks like "quiet, nothing to report". The **dead-man's switch** closes that gap:

- After every completed cycle TLDR writes `heartbeat.json` next to the archive.
- `tldr-health.timer` runs `tldr --check-health` every 30 minutes.
- If the heartbeat is missing or older than `[health] max_age` (default `3h`), the checker sends a **high-priority Pushover alert** and exits non-zero (75).

This covers every failure mode: process crash (Restart=always usually self-heals first), a hang, an unhandled error that skips cycles, or a network that starts filtering port 53 so transfers silently fail. The only thing it cannot cover is the *checker* itself never running — for that, the absence of any message for days (or your host's own monitoring) is the backstop.

Check it manually any time:

```sh
tldr --config config.toml --check-health          # uses [health] max_age
tldr --config config.toml --check-health --max-age 90m
```

## Verifying

```sh
tldr --config config.toml --dry-run             # discovery only, no transfers
tldr --config config.toml --once --json         # one cycle
tldr --config config.toml --test-notification   # verify Pushover delivery
tldr --config config.toml --check-health        # verify the dead-man's switch
journalctl --user -u tldr -n 50                 # service logs
systemctl --user list-timers tldr-health.timer  # health timer schedule
```

A healthy run transfers the known-good zones (`.`, `arpa.`, `fj.`, `mw.`, `er.`, `xn--ygbi2ammx.`, plus whatever else still allows AXFR) and only emits notifications for `high` changes.
