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
scp -r Cargo.toml Cargo.lock crates src examples ubuntu@cybersecurity.theater:~/tldr-src/
ssh ubuntu@cybersecurity.theater '
  curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal &&
  ~/.cargo/bin/cargo build --release --locked --manifest-path ~/tldr-src/Cargo.toml
'

# 2. Install the binary, config, unit and credential file.
ssh ubuntu@cybersecurity.theater '
  mkdir -p ~/tldr-deploy/data ~/.config/systemd/user && chmod 700 ~/tldr-deploy &&
  cp ~/tldr-src/target/release/tldr ~/tldr-deploy/tldr &&
  chmod 600 ~/tldr-deploy/tldr.env 2>/dev/null || true
'
scp deploy/config.toml ubuntu@cybersecurity.theater:~/tldr-deploy/config.toml
scp deploy/tldr.service ubuntu@cybersecurity.theater:~/.config/systemd/user/

# 3. Enable it. Linger keeps the user service running without a login session.
ssh ubuntu@cybersecurity.theater '
  loginctl enable-linger ubuntu &&
  systemctl --user daemon-reload &&
  systemctl --user enable --now tldr.service
'
```

## Credentials

```
# ~/tldr-deploy/tldr.env  (mode 600, never committed)
PUSHOVER_APP_TOKEN=...
PUSHOVER_USER_TOKEN=...
```

If the tokens are unset, TLDR logs a warning and skips alerts; scanning and archiving continue normally.

## Verifying

```sh
tldr --config config.toml --dry-run       # discovery only, no transfers
tldr --config config.toml --once --json   # one cycle
tldr --config config.toml --test-notification  # verify Pushover delivery
journalctl --user -u tldr -n 50           # service logs
```

A healthy run transfers the known-good zones (`.`, `arpa.`, `fj.`, `mw.`, `er.`, `xn--ygbi2ammx.`, plus whatever else still allows AXFR) and only emits notifications for `high` changes.
