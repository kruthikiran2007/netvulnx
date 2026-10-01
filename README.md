# NetVulnX — Custom Network Vulnerability Scanner & Risk Assessment Platform

A realistic, safe-by-design network vulnerability assessment tool for
**authorized** environments: your own machines, lab VMs, and private networks
you have permission to test.

> **Milestone 5 status:** dashboards are live. The home page shows real
> aggregate stats (scans, assets, open ports, findings by severity), a risk
> score chart per completed scan, and the latest findings. A global **asset
> inventory** groups every observed IP across scans with first/last seen,
> open-port union, and worst severity — each with a per-scan timeline. The
> **attack-surface view** aggregates exposed services across completed scans
> (charts mirror the tables) plus a per-asset port map of the latest scan.
> Every number comes from the database; charts use Chart.js on real data.
> Reporting and scan comparison arrive in later milestones.

## Safety first

- Only `127.0.0.1` / `::1` and private addresses (`10.x`, `172.16–31.x`,
  `192.168.x`) are scannable by default. Public IPs are rejected unless
  explicitly opted in via `config.py` (`ALLOW_PUBLIC_TARGETS`).
- Every scan requires explicit authorization confirmation before any packet
  is sent. The confirmation is stored with the scan record.
- No brute force, no exploitation, no DoS, no stealth/evasion — by design.

## Setup

You need Python 3.10+.

```bash
# 1. Create an isolated Python environment for this project
python3 -m venv venv

# 2. Activate it (your shell prompt will show "(venv)")
source venv/bin/activate

# 3. Install dependencies (Flask, SQLAlchemy, pytest)
pip install -r requirements.txt

# 4. Run the tests
python -m pytest tests/ -v

# 5. Start the app
python run.py
```

Then open **http://127.0.0.1:5000** in your browser.

Try a first scan: target `127.0.0.1`, ports `80,443,22`.

## Project layout

```
netvulnx/
├── run.py                 # start the app: `python run.py`
├── config.py              # all settings in one place (safety controls live here)
├── requirements.txt       # Python dependencies
├── app/
│   ├── __init__.py        # Flask app factory (builds the app)
│   ├── models.py          # database tables: Scan, Asset, Port
│   ├── routes.py          # web pages: dashboard, scans, authorization gate, status API
│   ├── templates/         # HTML pages (rendered from real DB data)
│   └── static/style.css   # dark console theme
├── scanner/
│   ├── targets.py         # target parsing + scope validation (with tests)
│   ├── reachability.py    # host discovery — Phase 1 of a scan
│   ├── portscan.py        # TCP connect scan, bounded thread pool — Phase 2
│   ├── fingerprint.py     # banner grab + service ID with confidence — Phase 3
│   ├── engine.py          # scan orchestrator (background worker) — Phase 4
│   └── jobs.py            # job start / cancel / crash recovery
├── rules/                 # deterministic rule engine (Milestone 4)
├── tests/                 # pytest unit tests
└── docs/
    └── ARCHITECTURE.md    # how the pieces fit together
```

> **Upgrading from an earlier milestone?** The database schema changed (new tables
> and columns). During development, delete the old database before running
> the new code: `rm -f netvulnx.db` inside the project folder. (Proper
> database migrations arrive in a later milestone.)

## Milestones

1. **Foundation & safety** ✅ — scaffold, DB, UI shell, authorization gate, reachability
2. **Port scanning + fingerprinting** ✅ — real TCP connect scan, banner grabbing, service ID with confidence, background jobs, scan profiles
3. **HTTP/HTTPS + TLS analysis** ✅ — TLS handshake/cert/protocol analysis, HTTP redirect + security-header checks, safe DNS/SMTP/FTP service checks, TLS detection in fingerprinting
4. **Rule engine + risk scoring + evidence** ✅ — 15 deterministic rules turn observations into findings with evidence/confidence/impact/remediation; explainable risk score; no invented findings
5. **Dashboard, assets, attack-surface view** ✅ — real-data aggregates, risk chart, latest findings; global asset inventory with per-IP timelines; attack-surface view (service exposure + latest-scan port map); all charts mirror tables
6. **Reports, remediation tracking, scan comparison**
7. **Testing, hardening, documentation**
