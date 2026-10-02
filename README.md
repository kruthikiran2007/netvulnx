# NetVulnX — Custom Network Vulnerability Scanner & Risk Assessment Platform

A realistic, safe-by-design network vulnerability assessment tool for
**authorized** environments: your own machines, lab VMs, and private networks
you have permission to test.

> **Milestone 9 status:** complete. CVE mapping is in: when the scanner
> identifies a product *and* version (e.g. `Apache 2.4.1`), NetVulnX looks
> up real CVEs from the NVD, caches them (7-day TTL), and adds one finding
> per CVE — severity from the CVSS score, confidence "likely" (banner→CPE
> matching is heuristic), capped at 10 per service. No network → no CVE
> findings, never fake ones. All quality gates pass — **113 unit tests**,
> plus a live end-to-end scan against a fake Apache/2.4.1 that produced 10
> real CVE findings. See `docs/CVE_MAPPING.md`.

> **Milestone 8 status:** complete. Authentication is in: first-run admin
> setup, login/logout with salted password hashing (Werkzeug scrypt), a
> login gate on every page, and an append-only audit log (logins, scans,
> triage) with an admin viewer. The dev server is replaced by **waitress**
> (production-grade, Windows-friendly); `NETVULNX_DEBUG=1` still gives the
> Flask dev server. All quality gates pass — **100 unit tests + 11
> end-to-end checks** (real login flow + scan against a live server).

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
6. **Reports, remediation tracking, scan comparison** ✅ — printable HTML report per scan (browser Print → PDF); finding triage (open/acknowledged/resolved/false positive) with notes + remediation progress; scan diff (new/gone findings, opened/closed ports, risk delta)
7. **Testing, hardening, documentation** ✅ — 89 unit tests + 27 end-to-end checks; CSRF protection, security headers, hardened session cookies, secret-key hygiene; full doc set (API, TESTING, SECURITY, THREAT_MODEL, LIMITATIONS, ROADMAP, LAB_SETUP, DEVELOPMENT, PROJECT_REPORT)
8. **Authentication + production server** ✅ — first-run admin setup, login/logout with salted password hashing, login gate on all routes, append-only audit log with admin viewer; waitress production server (`NETVULNX_DEBUG=1` for Flask dev server); 100 unit tests + 11 end-to-end checks
