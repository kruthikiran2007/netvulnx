"""Unit tests for app/stats.py — pure aggregation helpers.

We build lightweight stand-in rows with SimpleNamespace instead of a
database: the helpers only read attributes, so this tests the real math.
"""
from datetime import datetime
from types import SimpleNamespace

from app.stats import (severity_counts, worst_severity, service_exposure,
                       inventory_rows, risk_history, recent_findings)


def _finding(severity, created=None):
    return SimpleNamespace(severity=severity,
                           created_at=created or datetime(2026, 10, 2, 12, 0))


def _port(service, port, asset_id, findings=()):
    return SimpleNamespace(service=service, port=port,
                           asset_id=asset_id, findings=list(findings))


def _asset(ip, scan_id, checked, ports=(), findings=(), hostname=None):
    return SimpleNamespace(ip_address=ip, hostname=hostname, scan_id=scan_id,
                           checked_at=checked, ports=list(ports),
                           findings=list(findings))


def test_severity_counts_always_has_all_keys():
    counts = severity_counts([_finding("high"), _finding("high"),
                              _finding("info")])
    assert counts == {"critical": 0, "high": 2, "medium": 0,
                      "low": 0, "info": 1}


def test_severity_counts_empty():
    assert severity_counts([]) == {"critical": 0, "high": 0, "medium": 0,
                                   "low": 0, "info": 0}


def test_worst_severity_picks_most_severe():
    assert worst_severity(["low", "critical", "medium"]) == "critical"
    assert worst_severity([]) is None
    assert worst_severity(["bogus"]) is None


def test_service_exposure_aggregates():
    ports = [
        _port("http", 80, 1, [_finding("medium")]),
        _port("http", 80, 2),                      # same service, other asset
        _port("http", 8080, 1, [_finding("low")]),  # same service, other port
        _port("ssh", 22, 1),
    ]
    rows = service_exposure(ports)
    by_svc = {r["service"]: r for r in rows}
    assert by_svc["http"]["exposures"] == 3
    assert by_svc["http"]["assets"] == 2
    assert by_svc["http"]["ports"] == [80, 8080]
    assert by_svc["http"]["worst"] == "medium"   # medium beats low
    assert by_svc["ssh"]["worst"] is None
    # Most exposed service first.
    assert rows[0]["service"] == "http"


def test_service_exposure_unknown_service_label():
    rows = service_exposure([_port(None, 9999, 1)])
    assert rows[0]["service"] == "unknown"


def test_inventory_groups_by_ip():
    a1 = _asset("10.0.0.5", 1, datetime(2026, 10, 1, 10, 0),
                ports=[_port("http", 80, 11)],
                findings=[_finding("high")], hostname="web1")
    a2 = _asset("10.0.0.5", 2, datetime(2026, 10, 2, 10, 0),
                ports=[_port("http", 80, 12), _port("ssh", 22, 12)],
                findings=[_finding("low")], hostname="web1-new")
    a3 = _asset("10.0.0.9", 2, datetime(2026, 10, 2, 10, 0))
    rows = inventory_rows([a1, a2, a3])
    assert len(rows) == 2
    web = next(r for r in rows if r["ip"] == "10.0.0.5")
    assert web["scans"] == 2
    assert web["open_ports"] == 2                       # union of ports
    assert web["findings"] == 2
    assert web["worst"] == "high"
    assert web["hostname"] == "web1-new"                # most recent wins
    assert web["first_seen"] == datetime(2026, 10, 1, 10, 0)
    assert web["last_seen"] == datetime(2026, 10, 2, 10, 0)
    other = next(r for r in rows if r["ip"] == "10.0.0.9")
    assert other["worst"] is None and other["findings"] == 0


def test_risk_history_only_completed_oldest_first():
    scans = [
        SimpleNamespace(id=1, name="b", status="completed", risk_score=5,
                        completed_at=datetime(2026, 10, 2, 9, 0),
                        created_at=datetime(2026, 10, 2, 8, 0)),
        SimpleNamespace(id=2, name="a", status="completed", risk_score=0,
                        completed_at=datetime(2026, 10, 1, 9, 0),
                        created_at=datetime(2026, 10, 1, 8, 0)),
        SimpleNamespace(id=3, name="c", status="failed", risk_score=99,
                        completed_at=None,
                        created_at=datetime(2026, 10, 3, 8, 0)),
    ]
    hist = risk_history(scans)
    assert [h["name"] for h in hist] == ["a", "b"]  # failed excluded
    assert hist[0]["risk"] == 0


def test_recent_findings_newest_first_limited():
    fs = [_finding("low", datetime(2026, 10, 2, h, 0)) for h in (8, 12, 10)]
    recent = recent_findings(fs, n=2)
    assert [f.created_at.hour for f in recent] == [12, 10]
