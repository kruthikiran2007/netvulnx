"""Scan comparison: pure diff helpers.

Compares two completed scans ("before" and "after") and reports what
changed. Pure functions over rows — unit-testable with SimpleNamespace.

A finding is identified by (rule_id, asset IP, port): the same bad
pattern on the same host:port in both scans is "the same finding".
A port is identified by (asset IP, port number).

Like stats.py, these helpers never invent data: everything in the
output comes from the rows passed in.
"""


def _finding_key(f):
    ip = f.asset.ip_address if f.asset else None
    port = f.port.port if f.port else None
    return (f.rule_id, ip, port)


def _port_key(p):
    ip = p.asset.ip_address if p.asset else None
    return (ip, p.port)


def compare_findings(before, after):
    """Diff findings between two scans.

    Returns {"new": [...], "gone": [...], "same": [...]} — lists of
    (before_row_or_None, after_row_or_None) pairs, each sorted by
    (severity rank, rule_id, ip, port) via the caller's sort key.
    Rows are the ORIGINAL objects passed in, not copies.
    """
    before_by_key = {_finding_key(f): f for f in before}
    after_by_key = {_finding_key(f): f for f in after}
    new = [(None, f) for k, f in after_by_key.items() if k not in before_by_key]
    gone = [(f, None) for k, f in before_by_key.items() if k not in after_by_key]
    same = [(before_by_key[k], after_by_key[k])
            for k in before_by_key if k in after_by_key]
    return {"new": new, "gone": gone, "same": same}


def compare_ports(before, after):
    """Diff open ports between two scans.

    Returns {"opened": [...], "closed": [...], "same": [...]} — lists of
    (before_row_or_None, after_row_or_None) pairs of the original rows.
    """
    before_by_key = {_port_key(p): p for p in before}
    after_by_key = {_port_key(p): p for p in after}
    opened = [(None, p) for k, p in after_by_key.items()
              if k not in before_by_key]
    closed = [(p, None) for k, p in before_by_key.items()
              if k not in after_by_key]
    same = [(before_by_key[k], after_by_key[k])
            for k in before_by_key if k in after_by_key]
    return {"opened": opened, "closed": closed, "same": same}


def summarize(before_scan, after_scan, finding_diff, port_diff):
    """Small honest summary dict for the comparison header."""
    n_new = len(finding_diff["new"])
    n_gone = len(finding_diff["gone"])
    return {
        "before_name": before_scan.name,
        "after_name": after_scan.name,
        "risk_before": before_scan.risk_score or 0,
        "risk_after": after_scan.risk_score or 0,
        "risk_delta": (after_scan.risk_score or 0) - (before_scan.risk_score or 0),
        "findings_new": n_new,
        "findings_gone": n_gone,
        "ports_opened": len(port_diff["opened"]),
        "ports_closed": len(port_diff["closed"]),
    }
