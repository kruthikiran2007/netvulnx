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

The project was built incrementally in seven milestones (Flask + SQLite,
Python standard-library networking, pytest), finishing with 89 unit
tests and 27 end-to-end checks passing, plus hardening (CSRF, security
headers, secret-key hygiene) and a full documentation set.

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
  (read-only protocol analyzers), `rules.py` (15 deterministic rules),
  `engine.py` + `jobs.py` (orchestration, background threads, cooperative
  cancellation, crash recovery).
- **Application layer** (`app/`): Flask factory, server-rendered Jinja
  routes, SQLAlchemy models (`Scan`, `Asset`, `Port`, `Finding`,
  `TlsInfo`, `HttpInfo`, `ServiceCheck`), `stats.py` / `diff.py` pure
  aggregation helpers, `csrf.py` protection.
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

- **89 unit tests** (pytest): target parsing, port states, fingerprint
  heuristics, TLS/HTTP/service analyzers, all 15 rules (positive *and*
  negative cases), stats/diff math, CSRF (forged POST → 403; valid token
  → 302), security headers, cookie flags. Network is mocked; DB tests use
  temp files.
- **27 end-to-end checks**: real scans through the real Flask app against
  fake HTTPS/HTTP/FTP/SMTP services on loopback — asserting real
  findings, real evidence strings, correct risk arithmetic, triage
  preserving evidence, and a two-scan comparison (risk delta −3, one
  finding gone, two ports closed).
- See `docs/TESTING.md` for methodology and `docs/LIMITATIONS.md` for
  what testing does *not* cover (no JS tests, no load tests, dev-server
  only).

## 8. Results

Against a lab of intentionally misconfigured fake services, NetVulnX
correctly identified weak TLS versions, missing security headers,
verbose service banners, and cleartext services — each with accurate
evidence and no false positives on the clean control service. The full
workflow (scan → authorize → triage → printable report → compare) runs
end-to-end in the browser. All quality gates pass: 89 unit + 27 e2e,
zero fabricated outputs by construction.

## 9. Limitations

Summarized from `docs/LIMITATIONS.md`: TCP-only scanning; no UDP, no
authenticated checks, no web crawling; version-based findings are
"potential" without a CVE feed; localhost dev server with no login
system; SQLite single-file storage; charts need the CDN (tables remain);
reports are point-in-time. Each limitation maps to a ROADMAP.md item.

## 10. Future work

Prioritized in `docs/ROADMAP.md`: CVE feed mapping, authentication,
scheduled scans with drift alerts, CSV/JSON export, Alembic migrations,
UDP scanning, authenticated protocol checks (SSH/SMB/RDP), and a
production deployment guide. Exploit capabilities are explicitly
excluded — permanently.

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
