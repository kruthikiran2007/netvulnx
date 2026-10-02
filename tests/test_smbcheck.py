"""Tests for the SMB protocol analyzer (Milestone 20).

A fake SMB server performs the real SMB2 + SMB1 negotiate handshakes
with configurable responses, so the tests exercise the actual wire
protocol — no mocks of the parser itself.
"""
import json
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from scanner import smbcheck
from rules import smb_rules


def _nbss(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_response(dialect=0x0300, sec_mode=0x03):
    header = struct.pack(
        "<4s H H I H H I I Q I I Q 16s",
        b"\xfeSMB", 64, 0, 0, 0, 1, 0x00000001, 0, 1, 0xFEFF, 0, 0,
        b"\x00" * 16)
    body = struct.pack(
        "<H H H H 16s I I I I Q Q",
        65, sec_mode, dialect, 0, b"\x11" * 16,
        0x00000007, 65536, 65536, 65536, 0, 0)
    return _nbss(header + body)


def _smb1_response(accept=True):
    header = struct.pack(
        "<4s B B B H B H H 8s H H H H H",
        b"\xffSMB", 0x72, 0, 0, 0, 0x88, 0xC001, 0,
        b"\x00" * 8, 0, 0, 0xFEFF, 0, 1)
    assert len(header) == 32
    dialect_index = 0 if accept else 0xFFFF
    body = struct.pack("<B H", 17, dialect_index) + b"\x00" * (17 * 2 - 2)
    return _nbss(header + body)


def _read_nbss(conn):
    hdr = b""
    while len(hdr) < 4:
        chunk = conn.recv(4 - len(hdr))
        if not chunk:
            raise OSError("closed")
        hdr += chunk
    length = int.from_bytes(hdr[1:4], "big")
    buf = b""
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


@pytest.fixture()
def fake_smb():
    """Yields a factory: fake_smb(dialect, sec_mode, smbv1) -> (host, port)."""
    servers = []

    def run(cfg, ready):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        srv.settimeout(10)
        servers.append(srv)
        ready.append(srv.getsockname()[1])
        # Handshake 1: SMB2 negotiate
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(10)
            req = _read_nbss(conn)
            assert req[0:4] == b"\xfeSMB"
            conn.sendall(_smb2_response(cfg["dialect"], cfg["sec_mode"]))
        # Handshake 2: SMB1 probe
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(10)
            req = _read_nbss(conn)
            assert req[0:4] == b"\xffSMB"
            conn.sendall(_smb1_response(cfg["smbv1"]))

    def make(dialect=0x0300, sec_mode=0x03, smbv1=False):
        ready = []
        t = threading.Thread(
            target=run,
            args=({"dialect": dialect, "sec_mode": sec_mode, "smbv1": smbv1},
                  ready),
            daemon=True)
        t.start()
        t.join(timeout=5)
        return "127.0.0.1", ready[0]

    yield make
    for srv in servers:
        srv.close()


def test_smb_negotiates_dialect_and_signing(fake_smb):
    host, port = fake_smb(dialect=0x0300, sec_mode=0x03, smbv1=False)
    res = smbcheck.check_smb(host, port)
    assert res["error"] is None
    assert res["dialect"] == 0x0300
    assert res["dialect_name"] == "SMB 3.0"
    assert res["signing_required"] is True
    assert res["smbv1_enabled"] is False


def test_smb_detects_smbv1_and_unsigned(fake_smb):
    host, port = fake_smb(dialect=0x0210, sec_mode=0x01, smbv1=True)
    res = smbcheck.check_smb(host, port)
    assert res["error"] is None
    assert res["smbv1_enabled"] is True
    assert res["signing_required"] is False
    assert res["signing_enabled"] is True


def test_smb_rules_flag_vulnerable_server(fake_smb):
    host, port = fake_smb(dialect=0x0210, sec_mode=0x00, smbv1=True)
    res = smbcheck.check_smb(host, port)
    row = SimpleNamespace(details=json.dumps(res))
    ctx = {"checks": {"smb_negotiate": row}}
    by_id = {r["id"]: r for r in smb_rules.RULES}
    v1 = by_id["smb-v1-enabled"]["match"](ctx)
    assert v1 is not None
    assert v1["_finding"]["severity"] == "high"
    sig = by_id["smb-signing-not-required"]["match"](ctx)
    assert sig is not None
    assert sig["_finding"]["severity"] == "medium"


def test_smb_rules_silent_on_hardened_server(fake_smb):
    host, port = fake_smb(dialect=0x0311, sec_mode=0x03, smbv1=False)
    res = smbcheck.check_smb(host, port)
    row = SimpleNamespace(details=json.dumps(res))
    ctx = {"checks": {"smb_negotiate": row}}
    for rule in smb_rules.RULES:
        assert rule["match"](ctx) is None


def test_smb_handles_closed_port():
    res = smbcheck.check_smb("127.0.0.1", 1)  # nothing listens here
    assert res["error"] is not None
    assert "summary" in res


def test_smb_rejects_garbage():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(b"this is not SMB at all")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    res = smbcheck.check_smb("127.0.0.1", port)
    srv.close()
    assert res["error"] is not None
