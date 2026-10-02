"""Outbound notifications (Milestone 16).

When a SCHEDULED scan completes, the schedule's webhook URL (Slack,
Teams, Discord, or any JSON receiver) gets a POST with the drift summary:
what's new and what's resolved since the last run. One-off manual scans
never notify — nobody asked for a standing alert on those.

Like everything that touches the network here: best-effort, 10s timeout,
never raises, never breaks the scan.
"""
import json
import urllib.request

TIMEOUT = 10


def _post_json(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NetVulnX/1.0"},
        method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.status


def build_payload(scan, drift):
    if drift is None:
        # First scheduled run: no baseline, so every finding is new.
        findings = scan.findings
        return {
            "text": (f"NetVulnX scheduled scan #{scan.id} ('{scan.name}') "
                     f"completed: first run, {len(findings)} finding(s)."),
            "scan_id": scan.id,
            "scan_name": scan.name,
            "target": scan.target_raw,
            "risk_score": scan.risk_score,
            "new_findings": len(findings),
            "resolved_findings": 0,
            "first_run": True,
            "top_new": [{"severity": f.severity, "title": f.title}
                        for f in findings[:5]],
        }
    new = drift["new"]
    resolved = drift["resolved"]
    return {
        "text": (f"NetVulnX scheduled scan #{scan.id} ('{scan.name}') "
                 f"completed: {len(new)} new, {len(resolved)} resolved "
                 f"finding(s) since the last run."),
        "scan_id": scan.id,
        "scan_name": scan.name,
        "target": scan.target_raw,
        "risk_score": scan.risk_score,
        "new_findings": len(new),
        "resolved_findings": len(resolved),
        "first_run": False,
        "top_new": [{"severity": f.severity, "title": f.title}
                    for f in new[:5]],
    }


def notify_scan_completed(scan, _post=None):
    """POST the drift summary to the schedule's webhook, if configured.

    Returns True if a notification was sent. Never raises — a dead
    webhook must not fail a scan. ``_post`` overrides the HTTP call
    (tests inject a fake).
    """
    post = _post or _post_json
    try:
        schedule = scan.schedule
        url = (schedule.webhook_url or "").strip() if schedule else ""
        if not url:
            return False
        from app.drift import drift_for_scan
        payload = build_payload(scan, drift_for_scan(scan))
        post(url, payload)
        return True
    except Exception:
        return False
