# TESTING.md — How NetVulnX Is Tested

Two layers: **unit tests** (fast, no network) and **end-to-end checks**
(real scans against fake local services). Both must pass before a
milestone is committed.

## Layer 1 — Unit tests (`tests/`, pytest)

```bash
cd ~/workspace/netvulnx
source venv/bin/activate
python -m pytest tests/ -q
```

- ~89 tests across `test_targets`, `test_portscan`, `test_fingerprint`,
  `test_tlscheck`, `test_httpcheck`, `test_servicecheck`, `test_rules`,
  `test_stats`, `test_diff`, `test_csrf`.
- **No real network:** DNS and sockets are faked with `unittest.mock`,
  so the suite passes identically on any machine, online or not.
- **No real database:** DB-touching tests build the app with a
  temporary SQLite file — never `netvulnx.db`.
- What they prove: parsing is correct, rules fire (and *don't* fire) on
  the right inputs, stats/diff math is right, CSRF rejects forged POSTs,
  security headers are present.

## Layer 2 — End-to-end checks (real scans, fake targets)

Because unit tests fake the network, each milestone is also verified with
**real scans against fake services on loopback** — real TCP connections,
real TLS handshakes, real HTTP, through the real Flask app via its test
client.

The throwaway scripts (e.g. `/tmp/verify_m6.py`, not committed) do this:

1. Start fake HTTPS (weak TLS), HTTP (missing headers), FTP (verbose
   banner), SMTP services on `127.0.0.1` high ports.
2. Drive the UI flow exactly like a user: `GET /scans/new` → extract the
   CSRF token → `POST /scans/new` → `POST .../authorize` with
   `confirm=yes` → poll `/api/scans/<id>/status` → `GET /scans/<id>`.
3. Assert on the database: expected findings exist with the right
   severities, evidence contains the real banner strings, risk score
   matches the formula, triage changes status but **not** evidence.
4. Shut everything down; temp database deleted.

Current bar (Milestone 6): **27/27 checks pass**, including a two-scan
comparison (11 findings/risk 13 vs 10/risk 10 → delta −3, 1 finding
gone, 2 ports closed).

## What is NOT tested (and why it matters)

- **No JavaScript testing** — charts are progressive enhancement; every
  chart has an adjacent data table that *is* asserted.
- **No production deployment testing** — the dev server is what's tested.
- **No adversarial testing of the scanner** against hostile servers
  beyond banner/header handling.
- **No performance/load testing** — scans are bounded by design, but
  "1000 hosts" behavior is unmeasured (see LIMITATIONS.md).

## Writing a new test

- Pure function? → `tests/test_<module>.py`, plain asserts, no fixtures.
- Rule? → feed it a fake observation dict; also test the negative case
  (rule must stay silent on missing/ambiguous data).
- Route? → build the app with a temp-DB config (see `test_csrf.py`),
  use the test client, include the CSRF token for POSTs.
- Keep tests deterministic: no sleeps waiting on the network, mock time
  where needed.
