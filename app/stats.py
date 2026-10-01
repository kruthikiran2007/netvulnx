"""Dashboard, inventory and attack-surface aggregations.

Every function here is PURE: it takes rows (SQLAlchemy objects or
lightweight stand-ins with the same attribute names) and returns plain
dicts/lists. They never touch the database and never invent data — all
numbers come from the rows passed in.

This makes the Milestone-5 pages trivially unit-testable: tests build
fake rows with SimpleNamespace and check the math, while the routes pass
real database rows.
"""
from datetime import datetime

from rules import SEVERITY_RANK, SEVERITIES


def severity_counts(findings):
    """Count findings per severity. Always returns all severities (0 if none)."""
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def worst_severity(severities):
    """Most severe name in an iterable, or None when empty/unknown.

    Uses SEVERITY_RANK from the rule registry so "worst" always agrees
    with the rule engine's own ordering.
    """
    ranked = [s for s in severities if s in SEVERITY_RANK]
    if not ranked:
        return None
    return min(ranked, key=lambda s: SEVERITY_RANK[s])


def service_exposure(ports):
    """Aggregate open ports by service name.

    Each port row needs: .service, .port, .asset_id, and .findings
    (a list of rows with .severity, may be empty).

    Returns a list of dicts sorted by exposure count (desc):
      service, exposures (asset:port pairs), assets (distinct),
      ports (sorted distinct port numbers), worst (worst finding
      severity seen on this service, or None).
    """
    by_service = {}
    for p in ports:
        svc = p.service or "unknown"
        entry = by_service.setdefault(svc, {
            "service": svc, "exposures": 0,
            "assets": set(), "ports": set(), "worst": None,
        })
        entry["exposures"] += 1
        entry["assets"].add(p.asset_id)
        entry["ports"].add(p.port)
        port_worst = worst_severity(f.severity for f in (p.findings or []))
        entry["worst"] = worst_severity(
            s for s in (entry["worst"], port_worst) if s)
    rows = [{
        "service": e["service"],
        "exposures": e["exposures"],
        "assets": len(e["assets"]),
        "ports": sorted(e["ports"]),
        "worst": e["worst"],
    } for e in by_service.values()]
    rows.sort(key=lambda r: (-r["exposures"], r["service"]))
    return rows


def inventory_rows(assets):
    """Group Asset rows by IP address into an inventory.

    Each asset row needs: .ip_address, .hostname, .checked_at, .scan_id,
    .ports (rows with .port/.service), .findings (rows with .severity).

    Returns dicts sorted by finding count then open-port count (desc):
      ip, hostname (most recent non-empty), first_seen, last_seen,
      scans (distinct scan count), ports ([(port, service)] sorted),
      open_ports, findings, worst.
    """
    def _when(a):
        return a.checked_at or datetime.min

    groups = {}
    # Newest first so the first row we see per IP gives hostname/last_seen.
    for a in sorted(assets, key=_when, reverse=True):
        g = groups.get(a.ip_address)
        if g is None:
            g = groups[a.ip_address] = {
                "ip": a.ip_address,
                "hostname": a.hostname,
                "first_seen": a.checked_at,
                "last_seen": a.checked_at,
                "scan_ids": set(),
                "port_map": {},
                "findings": 0,
                "worst": None,
            }
        else:
            if not g["hostname"] and a.hostname:
                g["hostname"] = a.hostname
            if a.checked_at and (g["first_seen"] is None
                                 or a.checked_at < g["first_seen"]):
                g["first_seen"] = a.checked_at
        g["scan_ids"].add(a.scan_id)
        for p in (a.ports or []):
            g["port_map"].setdefault(p.port, p.service or "unknown")
        sev_list = [f.severity for f in (a.findings or [])]
        g["findings"] += len(sev_list)
        g["worst"] = worst_severity(
            s for s in (g["worst"], worst_severity(sev_list)) if s)
    rows = [{
        "ip": g["ip"],
        "hostname": g["hostname"],
        "first_seen": g["first_seen"],
        "last_seen": g["last_seen"],
        "scans": len(g["scan_ids"]),
        "ports": sorted(g["port_map"].items()),
        "open_ports": len(g["port_map"]),
        "findings": g["findings"],
        "worst": g["worst"],
    } for g in groups.values()]
    rows.sort(key=lambda r: (-r["findings"], -r["open_ports"], r["ip"]))
    return rows


def risk_history(scans):
    """(name, risk score) pairs for completed scans, oldest first.

    Only completed scans appear: a cancelled/failed scan never finished
    rule evaluation, so its score would be misleading.
    """
    done = [s for s in scans if s.status == "completed"]
    done.sort(key=lambda s: s.completed_at or s.created_at)
    return [{"id": s.id, "name": s.name, "risk": s.risk_score or 0}
            for s in done]


def recent_findings(findings, n=5):
    """The n most recent findings, newest first."""
    return sorted(findings,
                  key=lambda f: f.created_at or datetime.min,
                  reverse=True)[:n]
