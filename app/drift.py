# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Drift detection (Milestone 10): what changed since the last scheduled run.

A "finding identity" is (rule_id, port number, title). A finding in the
new run whose identity wasn't in the previous run is NEW; an identity in
the previous run that's gone now is RESOLVED. This is heuristic on
purpose — it's a change signal for the operator, not a proof — and the UI
labels it as such.
"""
from app.models import Scan


def finding_key(finding):
    port_num = finding.port.port if finding.port else None
    return (finding.rule_id, port_num, finding.title)


def previous_completed_run(scan):
    """The most recent completed run of the same schedule before this scan."""
    if not scan.schedule_id:
        return None
    return (Scan.query
            .filter(Scan.schedule_id == scan.schedule_id,
                    Scan.status == "completed",
                    Scan.id < scan.id)
            .order_by(Scan.id.desc())
            .first())


def compare_scans(new_scan, old_scan):
    """Return {'new': [...], 'resolved': [...]} finding lists."""
    old_keys = {finding_key(f) for f in old_scan.findings}
    new_keys = {finding_key(f) for f in new_scan.findings}
    new = [f for f in new_scan.findings if finding_key(f) not in old_keys]
    resolved = [f for f in old_scan.findings if finding_key(f) not in new_keys]
    return {"new": new, "resolved": resolved}


def drift_for_scan(scan):
    """Drift vs the previous completed run, or None if not applicable."""
    prev = previous_completed_run(scan)
    if prev is None:
        return None
    result = compare_scans(scan, prev)
    result["previous_scan_id"] = prev.id
    result["previous_completed_at"] = prev.completed_at
    return result
