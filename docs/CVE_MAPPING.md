# CVE Mapping (Milestone 9)

When the scanner identifies **both a product and a version** on an open port
(e.g. `Apache 2.4.1` from an HTTP `Server:` header), NetVulnX looks up real,
publicly known vulnerabilities for that exact software from the
**NVD (National Vulnerability Database)** and adds one finding per CVE,
most severe first.

## How it works

1. **Banner → CPE.** `scanner/cve.py` maps the fingerprinted product name to
   an NVD CPE identifier, e.g. `Apache 2.4.1` →
   `cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*`. Only products with
   well-known CPEs are mapped (Apache, nginx, OpenSSH, vsftpd, ProFTPD,
   Postfix, MySQL, … — see `PRODUCT_CPE_MAP`). Anything else is skipped
   silently: no guess, no finding.
2. **CPE → CVEs.** The NVD API 2.0 is queried
   (`https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=…`).
3. **Cache.** Results are stored in the `cve_cache` table (7-day TTL), so
   repeat scans don't hammer the public API — and keep working offline
   until the cache expires.
4. **Findings.** One finding per CVE, capped at 10 per service, sorted by
   CVSS score descending. Severity comes from the CVSS score
   (≥9 critical, ≥7 high, ≥4 medium, >0 low). Each finding links to its
   NVD entry.

## Honesty rules (read before trusting a CVE finding)

- **Confidence is "likely", never "confirmed".** The chain
  banner → product → CPE is heuristic: a lying or generic banner
  (`Server: Apache`) can match CVEs that don't apply.
- **"Affected" ≠ "exploitable here".** A CVE known to affect Apache 2.4.1
  doesn't prove *your* host is exploitable — the vulnerable module may be
  disabled, the port may be firewalled, a backported distro patch may
  already be applied. Every CVE finding says this in plain language.
- **No network at scan time → no CVE findings.** The lookup failing (offline,
  API error, rate limit) degrades silently: the rest of the scan is
  unaffected, and nothing is invented to fill the gap.
- **Capped, not exhaustive.** The API returns up to 50 CVEs per CPE and the
  scan reports the 10 most severe. An old version can have hundreds of
  CVEs; the finding tells you the total count so you know you're seeing
  the worst, not all.

## Rate limits

The NVD allows 5 requests per 30 seconds without an API key — plenty for
normal scans, since each unique product/version is fetched once and then
cached. If you scan many distinct versions at once and hit the limit, the
lookup simply returns nothing for that service (no crash, no fake data).

## For developers

- `scanner/cve.py` — CPE building (`build_cpe`), NVD client
  (`_fetch_from_nvd`), cache (`_cache_get`/`_cache_put`), CVSS→severity
  (`cvss_to_severity`), and the orchestrator (`lookup_cves`).
- `rules/cve_rules.py` — the `cve-known-vulnerabilities` rule; its `match`
  returns evidence containing the CVE list.
- `scanner/engine.py::_add_cve_findings` — expands the evidence into
  per-CVE findings (the rule engine itself only does one-finding-per-rule,
  so CVE expansion is the one deliberate exception).
- Tests: `tests/test_cve.py` — all network access is faked; the NVD is
  never touched by the test suite.
