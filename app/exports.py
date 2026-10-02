"""Finding exports (Milestone 11): CSV and JSON downloads of a scan.

Machine-readable output for ticketing tools, spreadsheets, and further
analysis — alongside the printable HTML report. Every value comes from
the database; nothing is invented.
"""
import csv
import io
import json


CSV_COLUMNS = [
    "finding_id", "title", "severity", "confidence", "status",
    "rule_id", "port", "service", "product", "version",
    "description", "impact", "remediation", "references", "evidence",
]


def _finding_row(f):
    port = f.port
    refs = f.references or "[]"
    try:
        refs = ", ".join(json.loads(refs))
    except (ValueError, TypeError):
        pass
    return {
        "finding_id": f.id,
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "status": f.status,
        "rule_id": f.rule_id,
        "port": port.port if port else "",
        "service": port.service if port else "",
        "product": port.product if port else "",
        "version": port.version if port else "",
        "description": f.description or "",
        "impact": f.impact or "",
        "remediation": f.remediation or "",
        "references": refs,
        "evidence": f.evidence or "",
    }


def findings_csv(scan):
    """CSV text of all findings in a scan, most severe first."""
    from rules import SEVERITY_RANK
    findings = sorted(scan.findings,
                      key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id))
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for f in findings:
        writer.writerow(_finding_row(f))
    return buf.getvalue()


def scan_json(scan):
    """Full scan as a JSON-serializable dict: metadata, assets, findings."""
    return {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target_raw,
            "target_type": scan.target_type,
            "profile": scan.profile,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "created_at": str(scan.created_at),
            "completed_at": str(scan.completed_at),
            "schedule_id": scan.schedule_id,
        },
        "assets": [
            {"ip_address": a.ip_address, "hostname": a.hostname,
             "ports": [
                 {"port": p.port, "service": p.service,
                  "product": p.product, "version": p.version,
                  "confidence": p.confidence}
                 for p in a.ports]}
            for a in scan.assets
        ],
        "findings": [_finding_row(f) for f in scan.findings],
        "exported_by": "NetVulnX",
    }
