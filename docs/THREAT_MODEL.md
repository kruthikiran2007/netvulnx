# THREAT_MODEL.md — NetVulnX Threat Model

A threat model is a structured way of asking: *what can go wrong, who could
cause it, and what did we do about it?* This one is deliberately simple —
STRIDE-lite for a localhost defensive tool.

## 1. What we are protecting

**Assets:**
- **A1** — Scan results (what is open/vulnerable on the user's own lab).
- **A2** — The user's session (which grants scan control).
- **A3** — The operator's machine & lab network (must not be harmed by scans).
- **A4** — Third parties on the internet (must not be scanned or harmed).

**Trust boundaries:**
- Browser ↔ Flask app (localhost HTTP).
- Flask app → target hosts (raw TCP/TLS/HTTP probes).
- Flask app → SQLite file on disk.

## 2. Threats & mitigations

### T1 — Attacker scans someone else's systems (abuse of the tool)
*STRIDE: Abuse.* The operator points NetVulnX at infrastructure they don't own.
- **Mitigations:** allow-listed target ranges only (private/loopback by
  default, public rejected); explicit per-scan authorization gate; no stealth
  or evasion features exist to abuse; scans are ordinary, identifiable TCP
  connections with timeouts.
- **Residual risk:** an operator with written permission can flip
  `ALLOW_PUBLIC_TARGETS`. That is an intentional, auditable opt-in.
  *Owner of risk: the operator.*

### T2 — CSRF: a malicious site triggers scans via the operator's browser
*STRIDE: Spoofing / Elevation.*
- **Mitigations:** per-session CSRF token on every POST, validated in
  `before_request`; state-changing actions are POST-only; `SameSite=Lax`
  cookies.
- **Residual risk:** low while the app is localhost-only.

### T3 — Attacker reads or tampers with scan results
*STRIDE: Information disclosure / Tampering.*
- **Mitigations:** app binds to `127.0.0.1` only — not reachable from the
  LAN; Jinja autoescaping prevents stored-XSS via banners/evidence;
  `_safe_back` blocks open redirects; SQLAlchemy bound parameters block
  SQL injection.
- **Residual risk:** **no authentication** — anyone with access to the
  machine (or the `netvulnx.db` file) can read everything. *Do not expose
  the port to untrusted networks.*

### T4 — Session forgery via known secret key
*STRIDE: Spoofing.*
- **Mitigations:** `SECRET_KEY` from `NETVULNX_SECRET_KEY` env var; loud
  startup warning when the dev fallback is in use; `HttpOnly` cookies.
- **Residual risk:** dev fallback is guessable — fine for local learning,
  must be replaced for any shared deployment.

### T5 — Scan harms the target (DoS, crashes, data loss)
*STRIDE: Denial of service (against the target).*
- **Mitigations:** non-destructive probes only (connect, read banner,
  handshake, polite HTTP GET, protocol greetings); bounded concurrency
  (32 workers); short timeouts; cooperative cancellation; no payloads,
  no exploit code, no fuzzing, no auth attempts.
- **Residual risk:** minimal — the traffic resembles a normal client
  connecting. Fragile embedded devices could still dislike port scans;
  scan only systems you are allowed to test.

### T6 — Malicious server attacks the scanner (banner/header injection)
*STRIDE: Tampering / Information disclosure.*
- **Mitigations:** banners and headers are stored as plain text and
  HTML-escaped on render; JSON columns parsed defensively; TLS certs are
  *inspected*, never trusted for decisions beyond their presented fields;
  SNI/hostname handling is conservative.
- **Residual risk:** low.

### T7 — Database file stolen or corrupted
*STRIDE: Information disclosure / Tampering.*
- **Mitigations:** SQLite file lives in the project dir with normal file
  permissions; no network exposure of the DB.
- **Residual risk:** file is unencrypted at rest — anyone with disk access
  can read scan history. Acceptable for a local lab tool; note it in
  SECURITY.md §4.

### T8 — Dependency / supply-chain compromise
*STRIDE: Tampering.*
- **Mitigations:** tiny dependency surface (Flask, Flask-SQLAlchemy,
  pytest); no network-fetched code at runtime except the Chart.js CDN
  (pinned by the CSP to `cdn.jsdelivr.net`, charts degrade to tables
  offline).
- **Residual risk:** standard for any Python project — pin versions for
  releases (see ROADMAP.md).

## 3. What is explicitly out of scope

- Protecting against a **malicious operator** (someone who deliberately
  misuses their own copy) — no tool can do that; the safety gates make
  *accidental* misuse hard instead.
- Network-level attackers between browser and app — the app is
  localhost-only by design, so this reduces to machine compromise, which
  is out of scope.
- Availability of the app itself under adversarial load — it's a dev
  server, not hardened infrastructure.

## 4. Assumptions

1. The operator is authorized to scan every target they enter.
2. The machine running NetVulnX is not shared with adversaries.
3. `NETVULNX_SECRET_KEY` is set for any non-local use.
4. The lab network tolerates ordinary connection attempts.

If an assumption breaks, re-read SECURITY.md §3 (known gaps) before
continuing.
