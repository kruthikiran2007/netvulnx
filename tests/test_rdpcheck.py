# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for the RDP protocol analyzer (Milestone 20).

A fake RDP server performs the real X.224 Connection Request/Confirm
handshake with a configurable selected protocol, so the tests exercise
the actual wire protocol — no mocks of the parser itself.
"""
import json
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from scanner import rdpcheck
from rules import rdp_rules


def _read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


def _connection_confirm(selected):
    """X.224 CC with an RDP Negotiation Response selecting `selected`."""
    rdp_neg = struct.pack("<BBHI", 0x02, 0x00, 8, selected)
    x224 = struct.pack(">BBHHB", 6 + len(rdp_neg), 0xD0, 0, 1, 0) + rdp_neg
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224))
    return tpkt + x224


@pytest.fixture()
def fake_rdp():
    """Yields a factory: fake_rdp(selected) -> (host, port)."""
    servers = []

    def run(selected, ready):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(10)
        servers.append(srv)
        ready.append(srv.getsockname()[1])
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(10)
            tpkt = _read_exact(conn, 4)
            assert tpkt[0] == 3
            length = int.from_bytes(tpkt[2:4], "big")
            payload = _read_exact(conn, length - 4)
            assert payload[1] == 0xE0  # Connection Request
            conn.sendall(_connection_confirm(selected))

    def make(selected):
        ready = []
        t = threading.Thread(target=run, args=(selected, ready), daemon=True)
        t.start()
        t.join(timeout=5)
        return "127.0.0.1", ready[0]

    yield make
    for srv in servers:
        srv.close()


def test_rdp_detects_plain_rdp(fake_rdp):
    host, port = fake_rdp(0x00000000)
    res = rdpcheck.check_rdp(host, port)
    assert res["error"] is None
    assert res["selected_protocol"] == 0
    assert "no TLS" in res["selected_name"]


def test_rdp_detects_tls_without_nla(fake_rdp):
    host, port = fake_rdp(0x00000001)
    res = rdpcheck.check_rdp(host, port)
    assert res["error"] is None
    assert res["selected_protocol"] == 1


def test_rdp_detects_nla(fake_rdp):
    host, port = fake_rdp(0x00000002)
    res = rdpcheck.check_rdp(host, port)
    assert res["error"] is None
    assert res["selected_protocol"] == 2
    assert "NLA" in res["selected_name"]


def _ctx(res):
    row = SimpleNamespace(details=json.dumps(res))
    return {"checks": {"rdp_negotiate": row}}


def test_rdp_rules_flag_plain_rdp(fake_rdp):
    host, port = fake_rdp(0x00000000)
    res = rdpcheck.check_rdp(host, port)
    by_id = {r["id"]: r for r in rdp_rules.RULES}
    hit = by_id["rdp-plain-no-tls"]["match"](_ctx(res))
    assert hit is not None
    assert hit["_finding"]["severity"] == "high"
    assert by_id["rdp-no-nla"]["match"](_ctx(res)) is None


def test_rdp_rules_flag_tls_without_nla(fake_rdp):
    host, port = fake_rdp(0x00000001)
    res = rdpcheck.check_rdp(host, port)
    by_id = {r["id"]: r for r in rdp_rules.RULES}
    assert by_id["rdp-plain-no-tls"]["match"](_ctx(res)) is None
    hit = by_id["rdp-no-nla"]["match"](_ctx(res))
    assert hit is not None
    assert hit["_finding"]["severity"] == "medium"


def test_rdp_rules_silent_with_nla(fake_rdp):
    host, port = fake_rdp(0x00000008)
    res = rdpcheck.check_rdp(host, port)
    ctx = _ctx(res)
    for rule in rdp_rules.RULES:
        assert rule["match"](ctx) is None


def test_rdp_handles_closed_port():
    res = rdpcheck.check_rdp("127.0.0.1", 1)
    assert res["error"] is not None
    assert "summary" in res


def test_rdp_rejects_garbage():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(b"definitely not RDP")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    res = rdpcheck.check_rdp("127.0.0.1", port)
    srv.close()
    assert res["error"] is not None
