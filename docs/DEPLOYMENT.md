# Deployment Guide (Milestone 17)

NetVulnX runs anywhere Python runs. Three paths, simplest first.

## Option A — Docker (recommended)

```bash
# 1. Pick a secret (keep it safe — it signs sessions):
export NETVULNX_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 2. Build and start:
docker compose up -d --build

# 3. Open http://127.0.0.1:5000 and create the admin account.
```

The database lives in the `netvulnx-data` volume: scans, users, and the
audit log survive restarts and rebuilds. Upgrade with
`docker compose up -d --build` — the app runs its Alembic migrations
automatically on startup.

Logs: `docker compose logs -f`.

## Option B — HTTPS with Caddy (for real networks)

NetVulnX itself speaks plain HTTP. In front of it, Caddy terminates TLS
with automatic certificates:

```
# /etc/caddy/Caddyfile
scanner.example.com {
    reverse_proxy 127.0.0.1:5000
}
```

```bash
systemctl reload caddy
```

Then tell NetVulnX it's behind HTTPS so cookies get the Secure flag:

```bash
NETVULNX_COOKIE_SECURE=1
```

(With Docker Compose: `NETVULNX_COOKIE_SECURE=1 docker compose up -d`.)

## Option C — systemd on a VM

```ini
# /etc/systemd/system/netvulnx.service
[Unit]
Description=NetVulnX vulnerability scanner
After=network.target

[Service]
User=netvulnx
WorkingDirectory=/opt/netvulnx
Environment=NETVULNX_SECRET_KEY=<long random value>
Environment=NETVULNX_COOKIE_SECURE=1
ExecStart=/opt/netvulnx/venv/bin/python run.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now netvulnx
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NETVULNX_SECRET_KEY` | `dev-only-change-me` | Signs sessions/CSRF. **Set this** anywhere beyond your laptop — the app warns on startup otherwise. |
| `NETVULNX_HOST` | `127.0.0.1` | Bind address. `0.0.0.0` only behind a firewall/reverse proxy (Docker sets this). |
| `NETVULNX_DB_PATH` | `<project>/netvulnx.db` | Where the SQLite database lives (Docker: `/data/netvulnx.db`). |
| `NETVULNX_COOKIE_SECURE` | `0` | Set to `1` when serving over HTTPS — cookies then only travel over TLS. |
| `NETVULNX_DEBUG` | unset | Set to `1` for Flask's dev server (never in production). |

## Pre-flight checklist for company use

- [ ] `NETVULNX_SECRET_KEY` set to a long random value.
- [ ] Served over HTTPS (`NETVULNX_COOKIE_SECURE=1`).
- [ ] Reachable only through the reverse proxy / firewall you intend.
- [ ] An admin account exists; extra users get least-privilege roles
      (viewer/operator), not admin.
- [ ] Scheduled scans point at webhooks so drift actually reaches someone.
- [ ] Backups: copy `netvulnx.db` (or the Docker volume) regularly — it
      holds every scan, finding, user, and audit event.

## What this does NOT make you

Docker + HTTPS is operational readiness, not a security audit. The
remaining honest limitations are in `docs/LIMITATIONS.md` (heuristic CVE
matching, no UDP scanning, SQLite scale ceiling). Read them before
promising anything to a client.
