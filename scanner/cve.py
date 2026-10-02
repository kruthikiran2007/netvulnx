"""CVE lookup: turn a fingerprinted product/version into real CVEs.

How it works:
  1. The fingerprinter gives us e.g. product="Apache", version="2.4.1".
  2. We map that to a CPE name (NVD's product identifier), e.g.
     ``cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*``.
  3. We ask the NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
     which CVEs affect that CPE, and read each one's CVSS score.
  4. Results are cached locally (``cve_cache`` table, 7-day TTL) so scans
     don't hammer the public API and repeat scans work offline.

Honesty notes (also in docs/CVE_MAPPING.md):
  - CPE matching is heuristic: banner "Apache" -> vendor "apache" is a
    guess, so CVE findings get confidence "likely", never "confirmed".
  - A CVE *affecting* version X does not prove this host is exploitable —
    findings say "known vulnerabilities exist for this software", not
    "this host is compromised".
  - No network at scan time (or API error) -> no CVE findings, never fake
    ones. The rest of the scan is unaffected.
"""
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = timedelta(days=7)
HTTP_TIMEOUT = 15
RESULTS_PER_PAGE = 50  # enough for the lookup; findings are capped separately
MAX_CVES_PER_SERVICE = 10  # findings emitted per port (top by CVSS)

# Banner product name (lowercased) -> (CPE vendor, CPE product).
# Only products the fingerprinter actually emits, with well-known CPEs.
PRODUCT_CPE_MAP = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "openbsd": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "filezilla": ("filezilla-project", "filezilla_server"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "exim": ("exim", "exim"),
    "mysql": ("oracle", "mysql"),
    "dropbear": ("matt_johnston", "dropbear"),
    "iis": ("microsoft", "internet_information_services"),
}


def clean_version(version):
    """Keep the leading numeric dotted part: '8.9p1' -> '8.9', '2.4.1' -> '2.4.1'."""
    if not version:
        return None
    m = re.match(r"(\d+(?:\.\d+)*)", str(version).strip())
    return m.group(1) if m else None


def build_cpe(product, version):
    """Map a fingerprinted product/version to a CPE 2.3 string, or None."""
    if not product or not version:
        return None
    key = str(product).strip().lower()
    # "Apache/2.4.1" style leftovers: take the first token.
    key = re.split(r"[\s/]+", key)[0]
    mapping = PRODUCT_CPE_MAP.get(key)
    if not mapping:
        return None
    ver = clean_version(version)
    if not ver:
        return None
    vendor, prod = mapping
    return f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"


def cvss_to_severity(score):
    """CVSS v3.x score -> our severity ladder."""
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_score(cve):
    """Best CVSS score from an NVD CVE item (v3.1 -> v3.0 -> v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            if data.get("baseScore") is not None:
                return data["baseScore"], data.get("vectorString", "")
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        data = entries[0].get("cvssData", {})
        if data.get("baseScore") is not None:
            # v2 scores run lower; map onto the same ladder conservatively.
            return data["baseScore"], data.get("vectorString", "")
    return None, ""


def _extract_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _fetch_from_nvd(cpe):
    """Query the NVD API for one CPE. Returns a list of CVE dicts."""
    params = urllib.parse.urlencode(
        {"cpeName": cpe, "resultsPerPage": RESULTS_PER_PAGE})
    req = urllib.request.Request(f"{NVD_API}?{params}",
                                 headers={"User-Agent": "NetVulnX/1.0"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        data = json.load(resp)
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, vector = _extract_score(cve)
        out.append({
            "id": cve.get("id", ""),
            "description": _extract_description(cve)[:500],
            "cvss": score,
            "vector": vector,
            "published": (cve.get("published") or "")[:10],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
        })
    # Most severe first — the finding cap takes from the top.
    out.sort(key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)))
    return out


def _cache_get(cpe):
    """Cached CVE list for this CPE, or None (miss/expired/any DB trouble)."""
    try:
        from app import db as _db
        from app.models import CveCache as _CveCache
        row = _db.session.get(_CveCache, cpe)
        if row and row.fetched_at:
            age = datetime.now(timezone.utc) - row.fetched_at.replace(
                tzinfo=timezone.utc)
            if age < CACHE_TTL:
                return json.loads(row.payload)
    except Exception:
        pass  # no app context, missing table, corrupt row — all non-fatal
    return None


def _cache_put(cpe, cves):
    """Store CVE list for this CPE. Never raises — cache is best-effort."""
    try:
        from app import db as _db
        from app.models import CveCache as _CveCache
        payload = json.dumps(cves)
        now = datetime.now(timezone.utc)
        row = _db.session.get(_CveCache, cpe)
        if row:
            row.payload, row.fetched_at = payload, now
        else:
            _db.session.add(_CveCache(cpe=cpe, payload=payload,
                                      fetched_at=now))
        _db.session.commit()
    except Exception:
        try:
            from app import db as _db2
            _db2.session.rollback()
        except Exception:
            pass


def lookup_cves(product, version, _fetch=None):
    """CVEs affecting this product/version. Cached; [] on any failure.

    ``_fetch`` overrides the network call (tests inject a fake).
    The local cache needs the Flask app DB; every DB touch is wrapped so
    a missing app context (or any DB trouble) degrades to "no cache"
    instead of crashing the scan.
    """
    cpe = build_cpe(product, version)
    if not cpe:
        return []
    cached = _cache_get(cpe)
    if cached is not None:
        return cached
    fetch = _fetch or _fetch_from_nvd
    try:
        cves = fetch(cpe)
    except Exception:
        return []  # offline / API error -> no CVE findings, scan continues
    _cache_put(cpe, cves)
    return cves
