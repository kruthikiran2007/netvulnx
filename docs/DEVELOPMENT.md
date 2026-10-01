# DEVELOPMENT.md — Developer Guide

How to work on NetVulnX without breaking it. Written for the project's
own future maintainers (including future-you).

## Setup

```bash
cd ~/workspace/netvulnx
python3 -m venv venv          # once
source venv/bin/activate      # every terminal session
pip install -r requirements.txt
python run.py                 # app at http://127.0.0.1:5000
```

- The virtualenv (`venv/`) isolates project packages from system Python.
  Never `pip install` with `sudo`.
- The dev database is `netvulnx.db` in the project root — created
  automatically. **Tests must never touch it** (see TESTING.md).

## Project layout

```
netvulnx/
├── run.py              # dev server entry point (localhost, debug)
├── config.py           # ALL settings in one place
├── app/
│   ├── __init__.py     # app factory, CSRF, security headers
│   ├── routes.py       # every page & action (server-rendered)
│   ├── models.py       # Scan, Asset, Port, Finding, TlsInfo, HttpInfo, ServiceCheck
│   ├── csrf.py         # per-session CSRF tokens
│   ├── diff.py         # scan-comparison helpers (pure functions)
│   ├── stats.py        # dashboard aggregation (pure functions)
│   └── templates/      # Jinja pages; _finding_card.html is shared
├── scanner/
│   ├── targets.py      # target parsing + allow-list validation
│   ├── portscan.py     # bounded TCP scan + fingerprinting
│   ├── tlscheck.py / httpcheck.py / servicecheck.py   # analyzers
│   ├── rules.py        # deterministic rule engine (15 rules)
│   ├── engine.py       # scan orchestration
│   └── jobs.py         # background threads, cancellation, recovery
├── tests/              # pytest suite (unit, no real network)
└── docs/               # this documentation set
```

## Conventions

1. **Pure logic lives in testable functions.** `stats.py`, `diff.py`, and
   the rule predicates take data in and return data out — no Flask, no DB,
   no sockets. That's why they're easy to unit-test.
2. **Routes are thin.** A route loads models, calls a helper, renders a
   template. If a route grows logic, extract it.
3. **Comments explain *why*, not *what*.** The codebase is also a teaching
   artifact — assume the reader is a beginner.
4. **Never fabricate.** If the scanner didn't measure it, the UI doesn't
   show it. No placeholder charts, no sample CVEs, no "AI detected".
5. **Safety gates stay.** Any new scan capability must pass through target
   validation and the authorization page. No silent network access.
6. **Bounded everything.** New concurrency needs a worker cap, a timeout,
   and a cancellation check.

## Adding a new rule (quick version)

Full guide: `docs/RULE_DEVELOPMENT.md`. Short version:

1. Write a predicate in `rules/` that reads measured fields
   (never guesses).
2. Give it: stable `rule_id`, severity, confidence tier (confirmed /
   likely / potential / informational), evidence, impact, remediation,
   references.
3. Add unit tests in `tests/test_rules.py` with a fake observation dict.
4. Run the suite. Rules must not fire on empty/unknown data.

## Database changes

There is no migration framework yet. For SQLite dev:

1. Add the column to the model in `app/models.py`.
2. Add the `ALTER TABLE` to `_ensure_columns()` in `app/__init__.py`
   (SQLite only supports simple `ADD COLUMN`).
3. Note it in ARCHITECTURE.md. (Replacing this with Alembic is on the
   roadmap.)

## Git workflow

- Small, honest commit messages: `Milestone N: what changed`.
- Commits used so far: `69a371d` (M1) → `7c31dc9` (M2) → `ddc87b6` (M3)
  → `5d603a7` (M4) → `2acdf59` (M5) → `ca1ec74` (M6).
- Identity: `NetVulnX Builder <builder@netvulnx.local>`.
- Never commit `netvulnx.db`, `venv/`, or `/tmp` scripts.

## Before you push a milestone

1. `python -m pytest tests/ -q` — all green.
2. End-to-end script against loopback fake services — all checks pass.
3. Update README milestone table + the relevant docs.
4. Re-read LIMITATIONS.md — did the milestone shrink it or grow it?
