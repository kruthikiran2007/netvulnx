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
  Done in Milestone 20: email password resets — single-use hashed
  tokens, 1-hour expiry, rate-limited, SMTP via NETVULNX_SMTP_*.
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

- [x] **UDP service discovery (done, Milestone 19).** Protocol-specific
  probes (DNS version.bind, SNMP sysDescr, NTP, NetBIOS-NS) with honest
  `open` vs `open|filtered` semantics — silence is never stored as a
  finding. SNMP `public` community flagged high. Unprivileged (no raw
  sockets); ICMP-based closed-port confirmation remains future work.
- [x] **Authenticated checks (done, Milestone 21).** Optional SSH
  credentials on the authorization page for a read-only `sshd -T` config
  audit — held in server memory only, never stored in the DB or logs.
  Requires paramiko (optional dependency).
- [x] **SSH algorithm analyzer (done, Milestone 18).** Real version +
  KEXINIT handshake, grades key exchange / host keys / ciphers / MACs —
  read-only, no login attempted.
- [x] **SMB + RDP analyzers (done, Milestone 20).** Real SMB2/SMB1
  negotiate and X.224 handshakes, read-only, no credentials — SMBv1
  detection, signing checks, RDP plain/TLS/NLA grading.
- [x] **More protocol analyzers (done, Milestone 21).** MySQL handshake
  version + EOL rules, PostgreSQL SSLRequest probe, Redis PING auth check —
  all read-only, no credentials.
- [x] **Network topology view (done, Milestone 21).** Observed hosts
  grouped into /24 zones, server-side SVG, worst-severity coloring. The
  legend is explicit: lines mean "same scan", not discovered routes.

## Nice to have

- [x] **Multi-user / team workspaces** with roles (viewer, operator, admin).
  ~~Done in Milestone 15: viewer (read-only), operator (runs/triages scans,
  manages schedules), admin (users, tokens, audit). Admin UI at /users;
  last-admin and self-demotion guards.~~
- [x] **Notification webhooks** (Slack/email) on scan completion or new
  critical findings. ~~Done in Milestone 16: per-schedule webhook URL,
  drift-summary JSON POST on every scheduled run completion.~~
- [x] **Baseline diffing in the UI (done, Milestone 21).** Pin a
  completed scan as the per-target baseline; the drift view shows new/gone
  findings and opened/closed ports vs the newest scan.
- [x] **Production deployment guide.** ~~Gunicorn + reverse proxy + TLS,
  `SESSION_COOKIE_SECURE`, pinned dependencies (`requirements.txt` with
  hashes), container image.~~ Done in Milestone 17: Dockerfile (non-root,
  volume for the DB), docker-compose.yml, and docs/DEPLOYMENT.md (Caddy
  HTTPS recipe, systemd unit, env-var reference, pre-flight checklist).
- [x] **i18n (done, Milestone 21).** Zero-dependency JSON catalogs,
  `{{ _('...') }}` in templates, session + browser language detection,
  English/Hindi shipped, fallback never renders blank.

## Explicitly not on the roadmap

- Exploit execution, payloads, brute force, credential attacks.
- Stealth/evasion techniques.
- Mass internet scanning features.
- Anything from SECURITY.md §6.

These are rejected on principle, not deferred for later.
