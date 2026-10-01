# NetVulnX Architecture (Milestone 6)

## The big picture

```
Your browser ──polls──▶ GET /api/scans/<id>/status   (live progress JSON)
    │                        ▲
    ▼                        │ commits progress + results
Flask web app  (app/__init__.py, app/routes.py)
    │  renders HTML from the database — never hardcoded numbers
    │  POST /scans/<id>/authorize → jobs.start_scan_job() (returns at once)
    ▼
SQLite database  (app/models.py: Scan, Asset, Port)
    ▲
    │  stores results (committed per host)
    ▼
Background worker thread  (scanner/jobs.py → scanner/engine.py)
    ├── Phase 1  reachability.py  host discovery ("is anything there?")
    ├── Phase 2  portscan.py      TCP connect scan, bounded thread pool
    ├── Phase 3  fingerprint.py   banner grab + protocol parsers → service + confidence
    └── Phase 4  storage          Asset + Port rows, real progress updates

scanner/targets.py  validate target + enforce scope (tested, unchanged role)
```

## Request flow: creating a scan

1. `GET /scans/new` — the form (`templates/new_scan.html`), now with a
   **scan profile** picker: Quick (20 ports), Standard (~120 ports),
   Deep (TCP 1–1024, no discovery shortcut), Custom (your port list).
   Each profile has clearly defined behavior, shown in the UI.
2. `POST /scans/new` — `parse_target()` validates the target; the profile
   resolves to a concrete port list (stored on the scan). Invalid input →
   back to the form with a plain-language error. Nothing stored, nothing
   touches the network.
3. `GET /scans/<id>/authorize` — shows exactly what will be scanned:
   target, profile + its behavior, host/port counts, honest worst-case
   time estimate, and the authorization statement.
4. `POST /scans/<id>/authorize` — **the safety gate**. Without the
   confirmation checkbox the scan is cancelled. With it, the scan is marked
   authorized (timestamp stored), set to `running`, and `start_scan_job()`
   launches the engine on a **background thread** — this request returns
   immediately.
5. `GET /scans/<id>` — results page. While running, JavaScript polls
   `/api/scans/<id>/status` every 2s and updates the progress bar from REAL
   values (hosts completed + per-host stage text like
   "Port scan 127.0.0.1: 320/1024"). On terminal status the page reloads
   to show the full Port/Service table. A Cancel button asks the worker
   to stop between phases/chunks.

## Why this shape?

- **App factory** (`create_app()`): tests build a fresh app without side
  effects; also runs `recover_interrupted()` so a restart mid-scan marks
  stale `running` rows as `interrupted` instead of lying forever.
- **Models, not raw SQL**: SQLAlchemy maps Python classes to tables and
  parameterizes every query — SQL injection is structurally impossible.
- **Validation before storage, storage before network**: each layer only
  runs after the previous one said "yes". The authorization gate sits
  between "we know the target" and "we touch the network".
- **Bounded thread pool** (`SCAN_WORKERS = 32`): at most 32 connections in
  flight. Network I/O releases Python's GIL, so threads are genuinely
  parallel here — and the bound keeps the scan gentle.
- **Honest port states**: `open` (handshake completed), `closed` (actively
  refused — host is up), `filtered` (timeout — "we don't know", not "closed").
- **Host discovery before port scan** (Quick/Standard): silent hosts are
  skipped quickly. Deep never skips; Custom always honors the exact ports
  the user named. Each choice is documented in the profile description.
- **Confidence, not guesses**: fingerprinting reports 90–99 for banner
  grammar matches, 75–89 for parsed protocol responses, 40–60 for
  explicitly-labeled port-number hints, 10–25 for unknown.
- **Cancellation + crash safety**: the worker checks a `threading.Event`
  between phases and port chunks; per-host commits keep partial results;
  `try/except/finally` guarantees no scan stays `running` forever.

## Milestone 3: service analysis (what's new)

After fingerprinting, the engine runs **Phase 3b — read-only service
analysis** per open port (`_analyze_service` in `scanner/engine.py`):

- **`scanner/tlscheck.py`** — TLS handshake inspection: negotiated version
  and cipher, weak-cipher flagging (by construction, deterministic), old
  protocol probes (TLS 1.0/1.1/1.2), certificate facts (subject, issuer,
  SANs, expiry, self-signed, hostname match). We deliberately do NOT verify
  the cert (`CERT_NONE`) — a scanner that refused untrusted certs could never
  report "expired / self-signed". We inspect; we don't trust. (One stdlib
  quirk documented in the code: with `CERT_NONE`, `getpeercert()` returns
  `{}`, so we decode the always-available binary form instead.)
- **`scanner/httpcheck.py`** — one careful `GET /` per web service using
  `http.client` directly (no auto-redirects, no cookies): manually-followed
  redirect chain (max 5), Server/X-Powered-By headers, security-header
  presence checklist (HSTS, CSP, X-Frame-Options, ...), http→https upgrade
  observation, directory-listing and default-page clues from a small
  body sniff (32 KB max).
- **`scanner/servicecheck.py`** — safe service-specific observations:
  DNS `version.bind` (CHAOS TXT over TCP), SMTP `EHLO` extensions +
  STARTTLS advertisement (we do NOT test open relay), FTP anonymous login
  attempt (`USER anonymous`, then `QUIT` — no listing, no download).
- **Fingerprinting learned TLS**: a TLS service answers no plaintext probe,
  so `fingerprint.py` now attempts one light read-only handshake (single,
  no protocol probes) and reports `https` at 90% confidence on any port.
  (This also fixed a real M2 bug: SMTP's `220` greeting was misidentified
  as FTP because both protocols greet with 220.)

Results land in three new tables — `TlsInfo`, `HttpInfo`, `ServiceCheck` —
holding measured facts plus deterministic derived flags (expired,
self-signed). **Risk judgments are deliberately absent**: the Milestone 4
rule engine will turn these observations into findings.

## What's next (Milestone 7)
Testing, hardening, documentation: the remaining required docs
(API.md, TESTING.md, SECURITY.md, THREAT_MODEL.md, LIMITATIONS.md,
ROADMAP.md, PROJECT_REPORT.md, LAB_SETUP.md, DEVELOPMENT.md), CSRF
protection, production SECRET_KEY handling, and a hardening pass.

## Milestone 6: reports, remediation tracking, scan comparison

- **HTML reports** (`/scans/<id>/report`) — generated on demand from live
  rows: scan summary, executive summary (risk, assets, ports, findings,
  severity badges), full finding cards (shared `_finding_card.html`
  include, read-only here), assets & open ports table, and a methodology &
  limitations section. A "Print / Save as PDF" button plus `@media print`
  CSS gives a clean PDF via the browser — no PDF library needed.
- **Remediation tracking** — `Finding.status` (`open`/`acknowledged`/
  `resolved`/`false_positive`, new columns via `_ensure_columns`) plus
  `status_note`/`status_updated_at`. `POST /findings/<id>/status` triages
  one finding; the referrer redirect is restricted to our own host
  (open-redirect safety). Scan detail shows "x of y closed" progress;
  the shared scan table gained an "Open" column. Triage is explicitly a
  human judgment — it never modifies measured evidence.
- **Scan comparison** (`/scans/compare`) — pick two completed scans;
  `app/diff.py` (pure, unit-tested) matches findings by
  (rule_id, IP, port) and ports by (IP, port), reporting new/gone
  findings, opened/closed ports, and the risk delta.

## Milestone 5: dashboard, asset inventory, attack-surface view

All presentation, no new scanning. Every number on these pages comes from
real database rows:

- **`app/stats.py`** — pure aggregation helpers with zero database access:
  `severity_counts`, `worst_severity`, `service_exposure` (per-service
  exposures/assets/ports/worst-severity), `inventory_rows` (assets grouped
  by IP: first/last seen, scan count, open-port union, finding totals),
  `risk_history` (completed scans only, oldest first), `recent_findings`.
  Pure = unit-testable with `SimpleNamespace` stand-ins (`tests/test_stats.py`).
- **Dashboard** (`/`) — stat cards (scans, assets, open ports, findings),
  findings-by-severity cards, a Chart.js risk-score bar chart per completed
  scan, and the 5 latest findings linking to assets/scans.
- **Asset inventory** (`/assets`) — one row per observed IP across all
  scans; **asset detail** (`/assets/<ip>`) — per-scan timeline (ports with
  worst severity, findings sorted most-severe-first).
- **Attack surface** (`/attack-surface`) — aggregates **completed scans
  only** (partial scans would misrepresent exposure): stat cards, a
  horizontal bar chart of exposures per service, a severity doughnut, a
  service-exposure table, and a per-asset port map of the latest completed
  scan with severity-coloured chips. Charts load Chart.js from a CDN; every
  chart mirrors an adjacent table, so the page is fully usable offline.
- **Model additions** — `Asset.findings` and `Scan.findings` relationships
  (backrefs `asset`/`scan`), so templates navigate Finding → scan/asset
  without extra queries.
- **Honesty rules kept**: a risk score of 0 is labelled "no rule matched",
  not "secure"; interrupted scans are excluded from aggregates; empty states
  explain what to do next instead of showing zeros silently.

## Milestone 4: rule engine + risk scoring (what's new)

After service analysis, the engine runs **Phase 3c — deterministic rule
evaluation** per open port (`_evaluate_rules` in `scanner/engine.py`):

- **`rules/`** — 15 rules in three modules (`tls_rules.py`, `http_rules.py`,
  `service_rules.py`). Each rule is a dict: stable `id`, `title`,
  `severity` (critical/high/medium/low/info), `confidence`
  (confirmed/likely/potential/informational), fixed explanatory text
  (`description`/`impact`/`remediation`/`references`), and a pure
  `match(ctx)` function. The context is built **only** from measured rows
  (Port + TlsInfo + HttpInfo + ServiceCheck) — rules do no I/O.
- **No invented findings.** `match` returns an evidence dict when the bad
  condition holds, `None` otherwise. No match → no `Finding` row, ever. An
  open port alone matches no rule, by design.
- **Two independent axes.** Severity = impact *if abused*; confidence = how
  sure the *measurement* is. A finding can be high-severity/likely or
  low-severity/confirmed — the UI shows both badges.
- **Bug isolation.** `evaluate()` runs each rule inside try/except: one
  broken rule is skipped, never crashes a scan. (This bit us during
  development — a rule touched `row.detail` instead of the real `details`
  column and silently never fired. The regression test
  `test_rules_against_real_model_attributes` runs every rule against real
  model instances so it can't happen again.)
- **`Finding` model** — `rule_id`, title, severity, confidence, evidence
  (JSON of measured values), impact, remediation, references (JSON list),
  timestamp. Linked to scan/asset/port; cascade-deleted with the scan.
- **Risk scoring** (`rules/scoring.py`) — a deliberately simple weighted
  sum: critical×10 + high×5 + medium×3 + low×1 (+info×0), stored on
  `Scan.risk_score` at completion. The formula is printed next to every
  score in the UI: a triage aid, not a security rating. 0 means "no rule
  matched", not "secure".
- **Schema migration helper** — `create_all()` creates missing tables but
  never adds columns, so `app/__init__.py` now runs `_ensure_columns()`
  (PRAGMA table_info + ALTER TABLE) for columns added to existing tables.
  Idempotent, runs every startup. (Proper Alembic migrations are still a
  later milestone.)
- **UI** — scan detail page gained a Findings section: risk-score card with
  the formula, severity counts, and one card per finding (severity +
  confidence badges, where, evidence table, impact, remediation,
  references). The shared scan table gained a Risk column. Full authoring
  guide: `docs/RULE_DEVELOPMENT.md`.
