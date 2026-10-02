# ROADMAP.md — Where NetVulnX Could Go Next

Every item here is **Planned / Future Enhancement** — not promised, not
present. Ordered roughly by value-to-effort for a student project.

## High value, moderate effort

- [x] **CVE mapping.** ~~Match detected software/version strings against a
  local CVE feed (e.g. NVD JSON) to turn "Potential" version findings into
  referenced, scored ones.~~ Done in Milestone 9: banner product/version →
  CPE → live NVD lookup (cached 7 days, `cve_cache` table), one finding per
  CVE with CVSS-based severity and "likely" confidence, capped at 10 per
  service. Honest about heuristic matching and "affected ≠ exploitable"
  (see CVE_MAPPING.md). Remaining: larger result windows for CVE-heavy
  products, optional NVD API key support.
- [x] **Authentication.** ~~Login (even simple local accounts) so the app can
  leave localhost safely.~~ Done in Milestone 8: first-run admin setup,
  salted password hashing, login gate, audit log (see AUTHENTICATION.md).
  Remaining: password reset, brute-force throttling, richer roles.
- [x] **Scheduled / recurring scans.** ~~Cron-like scheduling with drift
  alerts ("new finding since last Tuesday").~~ Done in Milestone 10:
  APScheduler ticker runs due schedules (daily/weekly); creation requires
  the recurring-authorization checkbox (audit-logged); drift banner on the
  scan detail page shows new/resolved findings vs the previous run.
- [x] **Export formats.** ~~CSV/JSON export of findings for ticketing tools;
  machine-readable report alongside the printable HTML.~~ Done in
  Milestone 11: per-scan CSV and JSON downloads, login-gated.
- [x] **Database migrations.** ~~Replace `_ensure_columns()` with Alembic so
  schema changes are versioned and reversible.~~ Done in Milestone 12:
  Alembic with an initial schema migration; pre-Alembic databases are
  stamped at head (never replayed, never lose data); `_ensure_columns`
  retained as a legacy safety net.

## High value, higher effort

- [ ] **UDP scanning.** Proper UDP service discovery (with retransmits and
  ICMP handling) — a genuinely hard problem, good dissertation material.
- [ ] **Authenticated checks.** Optional, user-supplied credentials for
  deeper assessment (SSH config audit, SMB signing checks) — with the
  secrets handled via the Secure Vault pattern, never stored in plaintext.
- [ ] **More protocol analyzers.** SSH (algorithms, host keys), SMB, RDP
  (CredSSP/TLS posture), database banners (MySQL/Postgres/Redis) —
  read-only, same philosophy as the existing five.
- [ ] **Network topology view.** Host relationships and trust zones from
  scan data.

## Nice to have

- [ ] **Multi-user / team workspaces** with roles (viewer, operator, admin).
- [ ] **Notification webhooks** (Slack/email) on scan completion or new
  critical findings.
- [ ] **Baseline diffing in the UI.** The `/scans/compare` engine exists;
  promote it to first-class "baseline vs now" tracking per asset.
- [x] **Production deployment guide.** ~~Gunicorn + reverse proxy + TLS,
  `SESSION_COOKIE_SECURE`, pinned dependencies (`requirements.txt` with
  hashes), container image.~~ Partially done in Milestone 8: waitress
  production server by default (`NETVULNX_DEBUG=1` for the dev server),
  pinned requirements, production checklist in AUTHENTICATION.md.
  Remaining: reverse-proxy + TLS recipe, container image.
- [ ] **i18n.** The UI strings are plain English in templates — extractable.

## Explicitly not on the roadmap

- Exploit execution, payloads, brute force, credential attacks.
- Stealth/evasion techniques.
- Mass internet scanning features.
- Anything from SECURITY.md §6.

These are rejected on principle, not deferred for later.
