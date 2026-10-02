# ROADMAP.md — Where NetVulnX Could Go Next

Every item here is **Planned / Future Enhancement** — not promised, not
present. Ordered roughly by value-to-effort for a student project.

## High value, moderate effort

- [ ] **CVE mapping.** Match detected software/version strings against a
  local CVE feed (e.g. NVD JSON) to turn "Potential" version findings into
  referenced, scored ones. Needs a safe offline feed + careful matching to
  avoid the false positives this project works hard to prevent.
- [x] **Authentication.** ~~Login (even simple local accounts) so the app can
  leave localhost safely.~~ Done in Milestone 8: first-run admin setup,
  salted password hashing, login gate, audit log (see AUTHENTICATION.md).
  Remaining: password reset, brute-force throttling, richer roles.
- [ ] **Scheduled / recurring scans.** Cron-like scheduling with drift
  alerts ("new finding since last Tuesday").
- [ ] **Export formats.** CSV/JSON export of findings for ticketing tools;
  machine-readable report alongside the printable HTML.
- [ ] **Database migrations.** Replace `_ensure_columns()` with Alembic so
  schema changes are versioned and reversible.

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
