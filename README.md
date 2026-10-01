# NetVulnX — Custom Network Vulnerability Scanner & Risk Assessment Platform

A realistic, safe-by-design network vulnerability assessment tool for
**authorized** environments: your own machines, lab VMs, and private networks
you have permission to test.

> **Milestone 1 status:** project foundation is in place. You can create a
> scan, pass the authorization gate, and run a real TCP reachability check.
> Port scanning, fingerprinting, the rule engine, risk scoring and reporting
> arrive in later milestones.

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
│   ├── models.py          # database tables: Scan, Asset
│   ├── routes.py          # web pages: dashboard, scans, authorization gate
│   ├── templates/         # HTML pages (rendered from real DB data)
│   └── static/style.css   # dark console theme
├── scanner/
│   ├── targets.py         # target parsing + scope validation (with tests)
│   └── reachability.py    # TCP reachability checks (Milestone-1 scan)
├── rules/                 # vulnerability rule engine (Milestone 4 — planned)
├── tests/                 # pytest unit tests
└── docs/
    └── ARCHITECTURE.md    # how the pieces fit together
```

## Milestones

1. **Foundation & safety** ✅ — scaffold, DB, UI shell, authorization gate, reachability
2. **Port scanning + fingerprinting** — real TCP connect scan, banner grabbing, service ID
3. **HTTP/HTTPS + TLS analysis** — headers, redirects, certificates, TLS config
4. **Rule engine + risk scoring + evidence** — the custom detection differentiator
5. **Dashboard, assets, attack-surface view** — all from real data
6. **Reports, remediation tracking, scan comparison**
7. **Testing, hardening, documentation**
