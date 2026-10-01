# SECURITY.md — NetVulnX Security Policy & Design

NetVulnX is a **defensive** security tool: it helps owners find weaknesses in
their own systems so they can fix them. This document explains the security
choices built into the project, what is intentionally out of scope, and how
to run it safely.

## 1. Scope of use — the most important rule

**Only scan systems you own or have explicit, written permission to assess.**

The app enforces this technically, not just in words:

- `config.py` → `ALLOW_PUBLIC_TARGETS = False` (default). The target parser
  (`scanner/targets.py`) **rejects public internet addresses** — loopback,
  `10/8`, `172.16/12`, and `192.168/16` are the only allowed ranges.
- Every scan requires an **explicit authorization click** on a confirmation
  page before any packet is sent (`/scans/<id>/authorize`).
- There is **no stealth, no evasion, no spoofing, no credential guessing,
  no brute force, no exploitation, no persistence, no malware, and no
  denial-of-service**. Every probe is an ordinary, well-formed connection
  attempt with short timeouts.

If you are assessing someone else's infrastructure (e.g. a client or an
employer), get written authorization first and only then consider flipping
`ALLOW_PUBLIC_TARGETS` — that flag exists for authorized enterprise use.

## 2. Secure-by-design choices

| Area | What NetVulnX does |
|---|---|
| Findings | Deterministic rule engine only (`rules/`). The app **never invents** vulnerabilities, CVEs, or statistics — open ports alone never become findings. |
| CSRF | Every POST form carries a per-session token (`app/csrf.py`), validated before each state-changing request. |
| Open redirects | After triage, redirects accept only URLs that begin with the app's own `request.host_url` (`_safe_back`). |
| XSS | All pages are server-rendered Jinja with autoescaping; findings store evidence as text, never rendered as HTML. The one JSON endpoint is consumed by first-party JS only. |
| SSRF | The scanner only connects to validated, allow-listed target ranges; user input cannot make the app fetch arbitrary internal URLs. |
| Injection | SQLAlchemy ORM with bound parameters — no string-built SQL. Target/port parsing rejects malformed input (`TargetError`). |
| Path traversal | Asset pages take an IP string used only in DB queries, never in file paths. |
| Deserialization | No `pickle`/`eval` anywhere. JSON columns are parsed with `json.loads` in a `try/except`. |
| Session cookies | `HttpOnly`, `SameSite=Lax`. (`Secure` is intentionally off — see §4.) |
| Response headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, and a Content-Security-Policy that allows only our inline scripts plus the Chart.js CDN. |
| Concurrency | Bounded worker pools (32), per-probe timeouts, cooperative cancellation — scans can't spiral into resource exhaustion. |

## 3. Known gaps (honest, not hidden)

1. **No login system.** Anyone who can reach the web UI can create scans and
   see results. This is acceptable for a localhost dev tool and a lab demo,
   but **do not expose the app to an untrusted network** without adding
   authentication (see ROADMAP.md).
2. **CSRF on a shared machine** is only as strong as the browser session —
   the dev fallback secret key (below) is the weaker link.
3. **Development secret key.** `config.py` falls back to
   `"dev-only-change-me"` if `NETVULNX_SECRET_KEY` is unset. The app logs a
   loud warning at startup in this case. Set the environment variable for
   any shared deployment: anyone who knows the key can forge session
   cookies.
4. **`debug=True`** in `run.py` — convenient locally, must be off if the
   app is ever served beyond localhost.
5. **No rate limiting** on scan creation — a local user could queue many
   scans; the bounded worker pool keeps this from becoming dangerous, but
   it is a UI-level gap.
6. **No database migrations** yet — schema changes use a small
   `_ensure_columns()` helper. Fine for SQLite dev, not for production.
7. Chart.js loads from a CDN — charts degrade gracefully to tables
   offline, but the CSP must keep allowing `cdn.jsdelivr.net`.

## 4. Deployment guidance

- Keep `host="127.0.0.1"` (localhost-only) unless you have added
  authentication and TLS termination in front of the app.
- Set `NETVULNX_SECRET_KEY` to a long random value
  (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`).
- Serve behind HTTPS (reverse proxy) and then enable
  `SESSION_COOKIE_SECURE = True`.
- Back up `netvulnx.db` — it holds your entire scan history.
- The database file contains scan results about *your own* lab; treat it
  with the same care as any internal assessment data.

## 5. Reporting a vulnerability in NetVulnX itself

This is a student project, not a commercial product with a bug-bounty
program — but reports are welcome and will be taken seriously. Please
describe the issue, the affected version/commit, and steps to reproduce,
**without** including exploit code against third parties. Responsible,
private disclosure is appreciated: give the maintainer a chance to fix
before publishing details.

## 6. What NetVulnX will never do

To remove any doubt: this project will not add exploit execution,
payload delivery, credential attacks, traffic interception, persistence
mechanisms, or anything designed to harm systems or evade detection. Pull
requests or feature requests in that direction will be declined.
