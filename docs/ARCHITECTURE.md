# NetVulnX Architecture (Milestone 1)

## The big picture

```
Your browser
    │
    ▼
Flask web app  (app/__init__.py, app/routes.py)
    │  renders HTML from the database — never hardcoded numbers
    ▼
SQLite database  (app/models.py: Scan, Asset)
    ▲
    │  stores results
    ▼
Scanner  (scanner/)
    ├── targets.py       validate target + enforce scope (tested)
    └── reachability.py  TCP connect checks (the Milestone-1 scan)
```

## Request flow: creating a scan

1. `GET /scans/new` — the form (`templates/new_scan.html`).
2. `POST /scans/new` — `parse_target()` + `parse_ports()` validate everything.
   Invalid input → back to the form with a plain-language error. Nothing is
   stored, nothing touches the network.
3. `GET /scans/<id>/authorize` — shows exactly what will be scanned, worst-case
   time estimate, and the authorization statement.
4. `POST /scans/<id>/authorize` — **the safety gate**. Without the confirmation
   checkbox the scan is cancelled. With it, the scan is marked authorized
   (timestamp stored) and `_run_reachability_scan()` executes.
5. `GET /scans/<id>` — results page, rendered from the `assets` table.

## Why this shape?

- **App factory** (`create_app()`): tests can build a fresh app without
  side effects; the dev server builds one for real use.
- **Models, not raw SQL**: SQLAlchemy maps Python classes to tables and
  parameterizes every query — SQL injection is structurally impossible.
- **Validation before storage, storage before network**: each layer only
  runs after the previous one said "yes". The authorization gate sits
  between "we know the target" and "we touch the network".
- **Sequential scanning (for now)**: one TCP connection at a time cannot
  overwhelm a target. Bounded parallelism arrives in Milestone 2, when full
  port scans make it necessary.

## What's next (Milestone 2)

`scanner/portscan.py` (bounded thread-pool TCP scan), `scanner/fingerprint.py`
(banner grabbing + service identification with confidence), background scan
jobs with real progress, and per-port results on the scan page.
