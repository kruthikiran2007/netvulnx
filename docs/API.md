# API.md — NetVulnX Endpoint Reference

NetVulnX is a **server-rendered web app**, not a REST API. This documents
every route: what it does, what it needs, and what it returns. There is
exactly one JSON endpoint (the progress poller); everything else returns
HTML.

Conventions: all POST routes require a valid CSRF token (`_csrf_token`
form field). Missing/invalid token → `403`. Unknown IDs → `404`.

## Pages (GET)

| Method & path | Purpose |
|---|---|
| `GET /` | Dashboard — scan/finding counts, severity breakdown, risk history chart, recent findings & scans. All numbers from the DB. |
| `GET /assets` | Global asset inventory — one row per IP across all scans. |
| `GET /assets/<ip>` | Asset timeline — every scan that saw this IP, newest first, with ports & findings. `404` if never seen. |
| `GET /attack-surface` | Exposure aggregation across **completed** scans: services, severities, latest open-port map per asset. |
| `GET /scans` | Scan history table (newest first), incl. open-findings count. |
| `GET /scans/new` | New-scan form (name, target, profile, ports). |
| `GET /scans/<id>` | Scan detail — progress, assets, ports, findings with triage forms, remediation bar, report button. |
| `GET /scans/<id>/authorize` | Authorization gate — shows target/ports, requires checkbox + confirm. **No network activity happens before this is submitted.** |
| `GET /scans/<id>/report` | Printable HTML assessment report (summary, findings, inventory, methodology, limitations). Browser print → PDF. |
| `GET /scans/compare?a=<id>&b=<id>` | Compare two completed scans: new/gone findings, opened/closed ports, risk delta. |

## Actions (POST)

| Method & path | Form fields | Effect |
|---|---|---|
| `POST /scans/new` | `name`, `target`, `profile` (quick/standard/deep/custom), `ports` (custom only) | Validates target & ports; creates scan as `awaiting_authorization`; → authorize page. Invalid input → form re-rendered with errors, nothing created. |
| `POST /scans/<id>/authorize` | `confirm=yes` (+ checkbox) | `confirm=yes` → marks authorized, starts background scan thread, → scan detail. Anything else → scan cancelled, nothing sent. Only works from `awaiting_authorization`. |
| `POST /scans/<id>/cancel` | — | Requests cooperative cancellation of a running scan. |
| `POST /findings/<id>/status` | `status` ∈ {open, acknowledged, resolved, false_positive}, `note` (optional) | Updates triage state + note + timestamp. **Never modifies measured evidence.** Redirects back (open-redirect-safe). |

## JSON

| Method & path | Returns |
|---|---|
| `GET /api/scans/<id>/status` | `{"status", "progress", "stage", "assets", "open_ports", "error"}` — polled by the scan-detail page for live progress. Real numbers only. |

## Data model (for report consumers)

- **Scan**: id, name, target, profile, ports, status
  (`awaiting_authorization`/`running`/`completed`/`failed`/`cancelled`/`interrupted`),
  progress, stage, `risk_score`, timestamps, authorization record.
- **Asset**: per scan per IP — hostname, latency, checked_at.
- **Port**: per asset — port number, state (`open`), service guess, banner.
- **Finding**: rule_id, severity (critical/high/medium/low/informational),
  confidence (confirmed/likely/potential/informational), evidence (measured),
  impact, remediation, references, triage status + note + timestamp.
- **TlsInfo / HttpInfo / ServiceCheck**: raw measured observations behind
  the findings.

Risk score: `critical×10 + high×5 + medium×3 + low×1` (informational adds 0).

## What there is no API for (by design)

- No programmatic scan submission without the web UI's authorization step.
- No bulk export endpoint yet (see ROADMAP.md).
- No authentication — so no API keys either. Keep it on localhost.
