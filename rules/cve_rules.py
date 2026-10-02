"""CVE mapping rule (Milestone 9).

One rule, ``cve-known-vulnerabilities``: when the fingerprinter identified a
product AND version we know how to map to a CPE, look up real CVEs from the
NVD and attach them as evidence. scanner/engine.py expands the evidence
into one finding per CVE (capped, most severe first) with severity taken
from each CVE's CVSS score.

Confidence is "likely", never "confirmed": banner -> product -> CPE is a
heuristic chain, and a CVE *affecting* a version doesn't prove this host
is exploitable. The finding text says exactly that.
"""
from scanner import cve as cve_lib


def _match_cve(ctx):
    port = ctx.get("port")
    if port is None:
        return None
    product = getattr(port, "product", None)
    version = getattr(port, "version", None)
    cpe = cve_lib.build_cpe(product, version)
    if not cpe:
        return None  # unknown product or no version -> no lookup, no finding
    cves = cve_lib.lookup_cves(product, version)
    if not cves:
        return None  # none known (or offline) -> honest silence
    return {"cpe": cpe,
            "product": product,
            "version": version,
            "cve_count": len(cves),
            "cves": cves[:cve_lib.MAX_CVES_PER_SERVICE]}


RULES = [
    {
        "id": "cve-known-vulnerabilities",
        # NOTE: title/severity below are placeholders — engine.py expands
        # this rule into per-CVE findings with real titles and CVSS-based
        # severities. They exist only to satisfy the rule schema guardrail.
        "title": "Known CVEs affect this software (see evidence)",
        "severity": "info",
        "confidence": "likely",
        "description": "Placeholder — replaced per CVE by the scan engine.",
        "impact": "Placeholder — replaced per CVE by the scan engine.",
        "remediation": "Placeholder — replaced per CVE by the scan engine.",
        "references": ["https://nvd.nist.gov/developers/vulnerabilities"],
        "match": _match_cve,
    },
]
