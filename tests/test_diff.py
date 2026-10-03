# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Unit tests for app/diff.py — pure scan-comparison helpers."""
from types import SimpleNamespace

from app.diff import compare_findings, compare_ports, summarize


def _asset(ip):
    return SimpleNamespace(ip_address=ip)


def _finding(rule_id, ip, port, severity="medium"):
    return SimpleNamespace(
        rule_id=rule_id, severity=severity,
        asset=_asset(ip),
        port=SimpleNamespace(port=port) if port else None)


def _port(ip, port, service="http"):
    return SimpleNamespace(port=port, service=service, asset=_asset(ip))


def test_compare_findings_new_gone_same():
    before = [_finding("r1", "10.0.0.1", 80), _finding("r2", "10.0.0.1", 22)]
    after = [_finding("r1", "10.0.0.1", 80), _finding("r3", "10.0.0.2", 443)]
    d = compare_findings(before, after)
    assert [f.rule_id for _, f in d["new"]] == ["r3"]
    assert [f.rule_id for f, _ in d["gone"]] == ["r2"]
    assert [f.rule_id for _, f in d["same"]] == ["r1"]
    # Pairs carry the original row objects.
    assert d["same"][0][0] is before[0] and d["same"][0][1] is after[0]


def test_compare_findings_same_rule_different_host_is_new():
    before = [_finding("r1", "10.0.0.1", 80)]
    after = [_finding("r1", "10.0.0.2", 80)]
    d = compare_findings(before, after)
    assert len(d["new"]) == 1 and len(d["gone"]) == 1 and not d["same"]


def test_compare_ports_opened_closed():
    before = [_port("10.0.0.1", 80), _port("10.0.0.1", 22)]
    after = [_port("10.0.0.1", 80), _port("10.0.0.1", 443)]
    d = compare_ports(before, after)
    assert [p.port for _, p in d["opened"]] == [443]
    assert [p.port for p, _ in d["closed"]] == [22]
    assert [p.port for _, p in d["same"]] == [80]


def test_summarize_delta():
    before = SimpleNamespace(name="a", risk_score=13)
    after = SimpleNamespace(name="b", risk_score=5)
    f_diff = {"new": [(None, 1)], "gone": [(1, None), (2, None)], "same": []}
    p_diff = {"opened": [], "closed": [(1, None)], "same": []}
    s = summarize(before, after, f_diff, p_diff)
    assert s["risk_delta"] == -8
    assert s["findings_new"] == 1 and s["findings_gone"] == 2
    assert s["ports_closed"] == 1 and s["ports_opened"] == 0


def test_empty_inputs():
    d = compare_findings([], [])
    assert d == {"new": [], "gone": [], "same": []}
    p = compare_ports([], [])
    assert p == {"opened": [], "closed": [], "same": []}
