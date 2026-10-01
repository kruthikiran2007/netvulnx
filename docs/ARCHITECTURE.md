# NetVulnX Architecture (Milestone 2)

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

## What's next (Milestone 3)

TLS/SSL analysis (certificate validity, protocol/cipher inspection —
read-only handshakes), HTTP security header checks, and service-level
observations feeding the finding pipeline. The rule engine, risk scoring,
and reporting arrive in Milestone 4.
