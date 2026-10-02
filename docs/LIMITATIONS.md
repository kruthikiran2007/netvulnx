# LIMITATIONS.md — What NetVulnX Cannot Do (Honest List)

A scanner that pretends to know everything is worse than one that admits
its blind spots. This is the complete, honest list.

## Scanning coverage

1. **TCP connect scans only.** No UDP, no SYN/half-open, no OS detection,
   no raw packets. UDP services (DNS on 53/udp, SNMP, NTP) are invisible
   to the port scanner — though the DNS *service check* can still query
   TCP/53 where offered.
2. **Discovery shortcut.** Quick/Standard profiles check ports 80, 443, 22
   first and may skip hosts silent on all three. Use Deep or Custom to
   check every host unconditionally.
3. **Only open ports get `Port` rows.** Closed/filtered totals are counted
   in memory during the scan but not persisted per host.
4. **No authenticated checks.** The scanner never logs in anywhere, so it
   can't assess anything behind authentication (admin panels, SSH configs
   beyond the banner, database contents).
5. **No web crawling or fuzzing.** HTTP analysis fetches `/` (and follows
   a small redirect chain) — it doesn't spider the site or test inputs.
6. **Version-based findings are "Potential".** When a banner claims
   `Server: X 1.2.3`, rules flag *known-bad patterns* (e.g. `Server`
   disclosing versions). Milestone 9 adds CVE mapping for products with
   known CPEs (see CVE_MAPPING.md) — but a CVE *affecting* a version is
   still not proof of exploitability on that host.

## Detection philosophy

7. **Open ports are not vulnerabilities.** The engine never creates a
   finding from "port X is open" alone — a finding needs a measured,
   explainable misconfiguration (weak TLS, missing security header, cleartext
   service, etc.).
8. **CVE findings are heuristic, not proof.** Since Milestone 9, findings
   can reference real CVE IDs (NVD-sourced, CVSS-scored) — but only at
   "likely" confidence, because banner→CPE matching is approximate and a
   CVE affecting a version doesn't prove this host is exploitable.
   Findings that aren't CVE-backed still reference standards and vendor
   docs (OWASP, Mozilla SSL guidance, RFCs).
9. **Deterministic, not AI.** There is no machine-learning detection and
   no LLM in the pipeline. Explanations in the UI are fixed templates
   written by the rule authors — consistent, auditable, and never
   hallucinating a vulnerability.
10. **Encrypted traffic content is opaque.** The TLS analyzer checks
    protocol versions, cipher names, and certificate fields — it does not
    (and cannot) inspect encrypted payloads.

## Platform & deployment

11. **Localhost server.** `run.py` serves with waitress (production-grade,
    pure Python) on `127.0.0.1:5000`; `NETVULNX_DEBUG=1` selects Flask's
    development server instead. Still localhost-only by default.
12. **Single-tier authentication.** Login, salted password hashing, and an
    audit log exist (Milestone 8), but there are no roles beyond
    admin/regular, no password reset, and no brute-force throttling.
    Fine for a small trusted team; harden before wider exposure.
13. **SQLite, single file.** Fine for one operator; not for concurrent
    teams. No migrations framework yet (`_ensure_columns()` only).
14. **Charts need the CDN.** Chart.js loads from `cdn.jsdelivr.net`;
    offline, charts don't render — but every chart sits next to a table
    with the same data.
15. **No rate limiting** on scan creation; a local user could queue many
    scans (bounded workers keep this from harming targets).

## Scope & safety

16. **Private/lab targets by default.** Public internet scanning is
    rejected unless `ALLOW_PUBLIC_TARGETS` is explicitly enabled for an
    authorized assessment.
17. **Reports are point-in-time.** A "clean" report means "nothing found
    with these checks on this date" — not "this system is secure."
18. **Triage is human judgment.** Marking a finding `resolved` records your
    decision; it doesn't verify the fix. Re-scan to confirm remediation.

## How to read this list in your project report

Examiners *like* limitation sections — they show you understand the
difference between a demo and a product. Pair each limitation above with
its ROADMAP.md counterpart to show you know what "done properly" would
look like.
