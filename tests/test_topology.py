# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for the network topology view (Milestone 21)."""
from types import SimpleNamespace

from app import topology as topo


def _asset(ip, scan_id=1, hostname=None):
    return SimpleNamespace(ip_address=ip, hostname=hostname, scan_id=scan_id)


def test_zone_of_ipv4():
    assert topo.zone_of("192.168.1.37") == "192.168.1.0/24"
    assert topo.zone_of("10.0.0.1") == "10.0.0.0/24"


def test_zone_of_garbage():
    assert topo.zone_of("not-an-ip") == "not-an-ip"


def test_build_topology_groups_and_edges():
    nodes = [
        (_asset("192.168.1.10", scan_id=1), "high", 3, ["ssh"]),
        (_asset("192.168.1.11", scan_id=1), None, 1, ["http"]),
        (_asset("10.0.0.5", scan_id=2), "low", 2, ["dns"]),
    ]
    zones, edges = topo.build_topology(nodes)
    assert sorted(zones) == ["10.0.0.0/24", "192.168.1.0/24"]
    assert len(zones["192.168.1.0/24"]) == 2
    # Same-scan pair gets an edge; cross-scan pair does not.
    assert ("192.168.1.10", "192.168.1.11") in edges
    assert ("10.0.0.5", "192.168.1.10") not in edges
    assert zones["192.168.1.0/24"][0]["color"] == "#ef6c00"  # high


def test_render_svg_contains_nodes_and_zones():
    nodes = [(_asset("192.168.1.10", hostname="web1"), "high", 3, ["ssh"])]
    zones, edges = topo.build_topology(nodes)
    svg = topo.render_svg(zones, edges)
    assert svg.startswith("<svg")
    assert svg.rstrip().endswith("</svg>")
    assert "192.168.1.0/24" in svg
    assert "web1" in svg
    assert "#ef6c00" in svg


def test_render_svg_empty():
    svg = topo.render_svg({}, [])
    assert "<svg" in svg and "</svg>" in svg


def test_esc():
    assert topo._esc('<a href="x">&') == "&lt;a href=&quot;x&quot;&gt;&amp;"
