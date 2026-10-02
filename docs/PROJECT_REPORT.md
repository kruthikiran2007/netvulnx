# PROJECT_REPORT.md — NetVulnX: Network Vulnerability Scanner & Risk Assessment Platform

*Final-year project report — B.Tech Cyber Security.*

---

## 1. Abstract

NetVulnX is a web-based **Network Vulnerability Scanner and Risk
Assessment Platform** built for authorized security assessments of
private/lab networks. Given a target (IP, hostname, or CIDR) and a scan
profile, it performs bounded TCP port scanning, passive service
fingerprinting, and read-only analysis of TLS, HTTP, DNS, SMTP, and FTP
services. A deterministic rule engine converts measured observations into
severity-ranked findings — each with evidence, confidence, impact,
remediation guidance, and references. The platform adds asset inventory,
attack-surface aggregation, remediation tracking, printable reports, and
scan-to-scan comparison on top of the scanner core.

The central design principle is **honesty**: the system never fabricates
vulnerabilities, CVEs, or statistics. Open ports alone never become
findings; every finding traces to something the scanner actually measured.
Safety is enforced technically — private/loopback-only targets by
default, an explicit per-scan authorization gate, non-destructive probes,
bounded concurrency, and no exploitation, brute-force, or evasion
capabilities of any kind.

The project was built incrementally in twenty-two milestones
(Flask + SQLite, Python standard-library networking, pytest, plus
paramiko for the authenticated SSH audit), finishing with 238 tests
passing, plus hardening (CSRF, security headers, secret-key hygiene,
login system with audit log) and a full documentation set.

## 2. Objectives

1. Build a **real, working** vulnerability scanner — not a dashboard mockup
   or an Nmap GUI wrapper.
2. Guarantee **result integrity**: deterministic detection, evidence for
   every finding, explicit confidence tiers, zero hallucinated output.
3. Enforce **safe operation by design**: authorized targets only,
   non-destructive probes, explicit user authorization before any scan.
4. Provide a **complete assessment workflow**: scan → findings → triage →
   report → compare, with asset history across scans.
5. Produce **project-grade documentation**: architecture, security policy,
   threat model, testing, user guide, and limitations.

## 3. Literature & background survey

- **Nmap / Nessus / OpenVAS**: the reference scanners. Nmap showed that
  fast, accurate port scanning is achievable with careful socket work;
  Nessus/OpenVAS showed the value of structured findings with remediation.
  NetVulnX borrows the *workflow* (discover → probe → analyze → report)
  but deliberately avoids raw-packet techniques (SYN scan, OS detection)
  to stay portable and safe without root privileges.
- **OWASP Secure Headers / Mozilla SSL Configuration Generator**: the
  authority behind the HTTP and TLS rules (which headers matter, which
  TLS versions/ciphers are weak).
- **CVSS philosophy**: severity should reflect exploitability *and*
  impact. NetVulnX uses a simpler fixed scale (critical/high/medium/low/
  informational) with a documented risk formula, appropriate for a
  teaching tool.
- **STRIDE threat modelling**: used to structure the project's own threat
  model (`docs/THREAT_MODEL.md`) — notable because student tools rarely
  model threats against *themselves*.

Gap addressed: most student "scanners" are port-listing scripts with
hardcoded fake findings. NetVulnX closes the integrity gap with a rule
engine that cannot report what it did not measure.

## 4. System architecture

Three layers (see `docs/ARCHITECTURE.md` for the full diagram):

- **Scanner layer** (`scanner/`): `targets.py` (parsing + allow-list),
  `portscan.py` (bounded TCP connect scan, banner grabbing, fingerprint
  heuristics), `tlscheck.py` / `httpcheck.py` / `servicecheck.py`
  (read-only protocol analyzers), `sshcheck.py` / `smbcheck.py` /
  `rdpcheck.py` / `dbcheck.py` (SSH/SMB/RDP/database handshake analyzers),
  `udpprobe.py` (DNS/SNMP/NTP/NetBIOS probes), `authchecks.py`
  (memory-only authenticated SSH config audit), `rules/` (deterministic
  rule registry), `engine.py` + `jobs.py` (orchestration, background
  threads, cooperative cancellation, crash recovery).
- **Application layer** (`app/`): Flask factory, server-rendered Jinja
  routes, SQLAlchemy models (`Scan`, `Asset`, `Port`, `Finding`,
  `TlsInfo`, `HttpInfo`, `ServiceCheck`, `User`, `Baseline`, ...),
  `stats.py` / `diff.py` pure aggregation helpers, `csrf.py`
  protection, Alembic migrations, login gate with audit log, email
  password resets, drift baselines, network topology (server-side SVG),
  and a zero-dependency i18n system (English/Hindi).
- **Presentation layer**: dark, professional UI; Chart.js charts that
  always sit beside data tables (graceful offline degradation);
  printable HTML reports via `@media print` CSS.

Key data flow: user authorizes → background thread scans → observations
persisted → rules evaluated → findings + risk score stored → dashboard,
assets, attack-surface, reports, and comparison all read from the same
database. There is exactly one JSON endpoint (progress polling);
everything else is HTML.

## 5. Implementation (milestones)

| Milestone | Delivered |
|---|---|
| M1 — Foundation | Flask/SQLite scaffold, authorization gate, target validation, private-scope enforcement, sequential TCP reachability. |
| M2 — Port scanning | Bounded concurrent scanning (32 workers), honest port states, cancellation, background jobs, live progress, crash recovery, passive banners, fingerprinting, scan profiles, persistent `Port` rows. |
| M3 — Service analysis | Read-only TLS (versions, ciphers, cert fields), HTTP (headers, cookies, redirects), DNS/SMTP/FTP checks; `TlsInfo`, `HttpInfo`, `ServiceCheck` models. |
| M4 — Rule engine | 15 deterministic rules (5 TLS, 7 HTTP, 3 service); `Finding` model with evidence/confidence/impact/remediation/references; risk score `10C+5H+3M+1L`; `RULE_DEVELOPMENT.md`. |
| M5 — Visibility | Dashboard with real DB stats, asset inventory + per-IP timeline, attack-surface aggregation, Chart.js over real data. |
| M6 — Workflow | Remediation triage (open/acknowledged/resolved/false_positive) that never touches evidence; printable HTML reports; scan-to-scan diff (new/gone findings, opened/closed ports, risk delta). |
| M7 — Hardening & docs | CSRF tokens on all POSTs, security headers + CSP, cookie flags, secret-key warning; 9 remaining docs; 7 new security tests. |
| M8 — Authentication | First-run admin setup, salted scrypt password hashing, login gate on all routes, append-only audit log, waitress production server. |
| M9 — CVE mapping | Product+version → real NVD lookups with CVSS severity, 7-day cache, honest "likely" confidence. |
| M10 — Scheduled scans | Cron-like scheduling with drift alerts ("new finding since last Tuesday"), webhook notifications. |
| M11 — Exports | CSV/JSON finding exports for ticketing tools. |
| M12 — Migrations | Alembic replaces `_ensure_columns()`; stamp-or-upgrade startup flow. |
| M13 — Login hardening | Throttling, lockout, session hygiene. |
| M14 — API tokens | Scoped API tokens for automation. |
| M15 — Team roles | Viewer/operator/admin RBAC. |
| M16 — Webhooks | Slack/email notifications on scan completion and drift. |
| M17 — Docker | Production deployment guide (reverse proxy + TLS checklist). |
| M18 — SSH analyzer | Real KEXINIT handshake; weak KEX/host-key/cipher/MAC grading. No login, ever. |
| M19 — UDP discovery | DNS/SNMP/NTP/NetBIOS-NS probes; honest open vs open\|filtered; SNMP public-community rule. |
| M20 — SMB/RDP + resets | Real SMB2/SMB1 negotiate (SMBv1, signing rules) and X.224 RDP handshake (plain/TLS/NLA rules); email password resets with single-use hashed tokens. |
| M21 — Final five | MySQL/PostgreSQL/Redis analyzers; memory-only authenticated SSH config audit; /24 topology map; per-target drift baselines; English/Hindi i18n. Roadmap 16/16 complete. |
| M22 — NoSQL analyzers | Real MongoDB wire-protocol hello (BSON/OP_MSG) detecting no-auth exposure + EOL versions; Elasticsearch open-cluster detection; Memcached exposure check. Dockerfile verified (.dockerignore, non-root, volume-backed DB) — image build requires a Docker host. |

## 6. The rule engine (core contribution)

Each rule is a pure predicate over measured observations, e.g.
"TLS 1.0 offered" → medium, confidence *confirmed* (the handshake
proved it); "Server header discloses version" → informational,
confidence *potential*. Confidence tiers (confirmed / likely /
potential / informational) are shown in the UI so users know *how
strongly* the evidence supports each finding. The engine is deliberately
conservative: ambiguous data produces no finding rather than a guessed
one. Adding a rule is documented in `RULE_DEVELOPMENT.md` and takes
~30 lines plus tests.

## 7. Testing & verification

- **238 tests** (pytest): target parsing, port states, fingerprint
  heuristics, every protocol analyzer (TLS/HTTP/SSH/SMB/RDP/MySQL/
  PostgreSQL/Redis/UDP) against fake wire-protocol servers, every rule
  (positive *and* negative cases), stats/diff/topology/i18n/baseline
  math, auth flows (login, CSRF, password reset, API tokens, RBAC),
  migrations (old-DB upgrade paths), security headers, cookie flags.
  2 tests skip in sandboxed CI (live UDP sockets blocked); 2 more skip
  without the optional paramiko dependency.
- **End-to-end checks**: real scans through the real Flask app against
  fake services on loopback — asserting real findings, real evidence
  strings, correct risk arithmetic, triage preserving evidence,
  baseline drift, and report rendering.
- See `docs/TESTING.md` for methodology and `docs/LIMITATIONS.md` for
  what testing does *not* cover (no JS tests, no load tests).

## 8. Results

Against labs of intentionally misconfigured fake services, NetVulnX
correctly identified weak TLS versions, missing security headers,
verbose service banners, cleartext services, SMBv1, unsigned SMB,
plain-RDP, EOL database versions, passwordless Redis, and weak sshd
settings — each with accurate evidence and no false positives on clean
control services. The full workflow (scan → authorize → triage →
printable report → compare → baseline drift) runs end-to-end in the
browser, in English or Hindi. All quality gates pass: 238 tests,
zero fabricated outputs by construction.

## 9. Limitations

Summarized from `docs/LIMITATIONS.md`: no UDP closed-port confirmation
(no ICMP); version-based findings stay "potential" without a CVE feed
match; SQLite single-file storage (fine for team scale, not
enterprise); the Docker image is documented but was not built in this
workspace; charts need the CDN (tables remain). The roadmap that once
listed these as future work is now 16/16 complete — remaining items
would be new scope, not gaps.

## 10. Future work

The `docs/ROADMAP.md` list is 16/16 complete. Any further work would be
new scope rather than planned gaps — candidates include a built and
published Docker image, load testing, and JavaScript test coverage.
Exploit capabilities remain explicitly excluded — permanently.

## 11. Conclusion

NetVulnX demonstrates that a student-built scanner can be both *real*
and *responsible*: real in that every finding is measured, every number
is computed, every chart is backed by database rows; responsible in that
safety constraints are code, not documentation. The project's lasting
artifact is not just the tool but the engineering discipline around it —
deterministic detection, explicit confidence, honest limitations, and a
threat model for the tool itself.

## 12. References

- OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
- Mozilla SSL Configuration Generator / Server Side TLS —
  https://ssl-config.mozilla.org/ / https://wiki.mozilla.org/Security/Server_Side_TLS
- RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2) — protocol version guidance
- RFC 9110 (HTTP Semantics) — header definitions
- Nmap Project — https://nmap.org/ (technique reference; not used as a dependency)
- Flask / SQLAlchemy / pytest documentation
- STRIDE threat modelling (Microsoft) — structure for `THREAT_MODEL.md`
