# Deploying TLDR to whisper.lan

TLDR runs as a container (primary, matching dmsh2) or as a systemd user service
(binary fallback, for hosts without Docker access).

## The egress problem

`whisper.lan` is on the same LAN as the development machine: **all TCP/UDP port
53 traffic is transparently intercepted**, so AXFR silently fails with injected
`REFUSED` responses. Successful zone transfers therefore require an unfiltered
egress path:

```
whisper ──ssh -D──► clean-egress-host ──port 53──► authoritative servers
```

Set `scan.socks5_proxy = "127.0.0.1:1080"` and `transport = "socks5"` in the
config, and keep a SOCKS tunnel running. The tunnel must use `-4`: IPv6 to the
egress host is broken from this LAN.

If no clean egress is reachable, the scanner still runs and archives discovery
results, but every transfer fails — it will never silently claim a zone is
untransferable when the real problem is local port-53 interception.

## Option A: Docker (primary)

```sh
# on whisper, in a checkout or copied deploy dir
cp deploy/config.toml ./config.toml      # edit paths/credentials
cp .env.example .env                     # fill in Pushover tokens
docker compose up -d
```

`compose.yaml` mounts `./config.toml` at `/config/config.toml` and `./data` at
`/data`, runs as uid/gid 1000, and restarts unless stopped, exactly like
`dmsh2`. The archive lives in `./data/archive`.

Build/publish comes from CI (`ghcr.io/tweedge/tldr`); to build locally:

```sh
docker build -t tldr .
```

## Option B: systemd user service (fallback)

Useful when Docker requires a password / root. Files live in `~/tldr-deploy`
and `~/.config/systemd/user`:

```sh
# from the dev machine
cargo build --release
scp target/release/tldr tweedge@whisper.lan:~/tldr-deploy/tldr
scp deploy/config.toml tweedge@whisper.lan:~/tldr-deploy/config.toml
scp deploy/tldr.service deploy/tldr-tunnel.service \
    tweedge@whisper.lan:~/.config/systemd/user/

# on whisper
loginctl enable-linger tweedge
systemctl --user daemon-reload
systemctl --user enable --now tldr-tunnel.service
systemctl --user enable --now tldr.service
journalctl --user -u tldr -f
```

`tldr-tunnel.service` runs `ssh -4 -N -D 127.0.0.1:1080` to the egress host with
keepalives and `Restart=always` (45s backoff to avoid tripping per-source-IP
throttling). `tldr.service` depends on it and reads Pushover credentials from
`~/tldr-deploy/tldr.env` (mode 600, never committed).

## Credentials

```
# ~/tldr-deploy/tldr.env or .env
PUSHOVER_APP_TOKEN=...
PUSHOVER_USER_TOKEN=...
```

## Verifying

```sh
tldr --config config.toml --dry-run            # discovery only
tldr --config config.toml --once --json        # one cycle, JSON report
journalctl --user -u tldr -n 50                # service logs
```

A healthy run logs `SOCKS5 proxy reachable`, transfers the known-good zones
(`.`, `arpa.`, `fj.`, `gp.`, `mw.`, `er.`, `xn--ygbi2ammx.`, plus whatever else
still allows AXFR), and only emits notifications for `high` changes.
