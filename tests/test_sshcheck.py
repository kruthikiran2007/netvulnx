# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for the SSH algorithm analyzer (Milestone 18).

A fake SSH server performs the real version + KEXINIT handshake with
configurable algorithm lists, so the tests exercise the actual wire
protocol — no mocks of the parser itself.
"""
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from scanner import sshcheck
from rules import ssh_rules


def _name_list(names):
    joined = ",".join(names).encode("ascii")
    return struct.pack(">I", len(joined)) + joined


def _kexinit_packet(kex, hostkey, ciphers, macs):
    payload = (b"\x14" + b"\x00" * 16
               + _name_list(kex) + _name_list(hostkey)
               + _name_list(ciphers) + _name_list(ciphers)
               + _name_list(macs) + _name_list(macs)
               + _name_list([]) + _name_list([])  # compression
               + b"\x00" + struct.pack(">I", 0))  # languages + first-follows
    padlen = 8 - ((1 + len(payload)) % 8)
    if padlen < 4:
        padlen += 8
    body = bytes([padlen]) + payload + b"\x00" * padlen
    return struct.pack(">I", len(body)) + body


WEAK = dict(
    kex=["diffie-hellman-group1-sha1", "curve25519-sha256"],
    hostkey=["ssh-dss", "ssh-rsa"],
    ciphers=["3des-cbc", "aes128-ctr"],
    macs=["hmac-md5", "hmac-sha2-256"],
)
STRONG = dict(
    kex=["curve25519-sha256", "diffie-hellman-group16-sha512"],
    hostkey=["ssh-ed25519", "rsa-sha2-512"],
    ciphers=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    macs=["hmac-sha2-256-etm@openssh.com"],
)


@pytest.fixture()
def fake_ssh():
    """Yields a factory: fake_ssh(algos) -> (host, port) of a fake server."""
    servers = []

    def run(algos, ready):
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
            conn.sendall(b"SSH-2.0-FakeSSH_9.9\r\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(64)
                if not chunk:
                    return
                buf += chunk
            conn.sendall(_kexinit_packet(**algos))

    def make(algos):
        ready = []
        t = threading.Thread(target=run, args=(algos, ready), daemon=True)
        t.start()
        t.join(timeout=5)
        return "127.0.0.1", ready[0]

    yield make
    for srv in servers:
        srv.close()


def test_ssh_enumerates_weak_algorithms(fake_ssh):
    host, port = fake_ssh(WEAK)
    res = sshcheck.check_ssh_algorithms(host, port)
    assert "error" not in res
    assert res["server_version"].startswith("SSH-2.0-FakeSSH")
    assert "diffie-hellman-group1-sha1" in res["kex_algorithms"]
    assert "ssh-dss" in res["host_key_algorithms"]
    assert "3des-cbc" in res["ciphers_c2s"]
    assert "hmac-md5" in res["macs_c2s"]


def _ctx_with(res):
    row = SimpleNamespace(details=__import__("json").dumps(res))
    return {"checks": {"ssh_algorithms": row}}


def test_ssh_rules_flag_weak_server(fake_ssh):
    host, port = fake_ssh(WEAK)
    res = sshcheck.check_ssh_algorithms(host, port)
    ctx = _ctx_with(res)
    by_id = {r["id"]: r for r in ssh_rules.RULES}
    kex = by_id["ssh-weak-kex"]["match"](ctx)
    assert kex is not None
    assert kex["_finding"]["severity"] == "high"
    assert "diffie-hellman-group1-sha1" in kex["_finding"]["description"]
    hk = by_id["ssh-weak-hostkey"]["match"](ctx)
    assert hk["_finding"]["severity"] == "high"
    assert "ssh-dss" in hk["_finding"]["description"]
    ci = by_id["ssh-weak-cipher"]["match"](ctx)
    assert ci["_finding"]["severity"] == "high"
    assert "3des-cbc" in ci["_finding"]["description"]
    mac = by_id["ssh-weak-mac"]["match"](ctx)
    assert mac["_finding"]["severity"] == "medium"
    assert "hmac-md5" in mac["_finding"]["description"]
    for r in ssh_rules.RULES:
        ev = r["match"](ctx)
        if ev:
            assert "ssh_config" not in ev["_finding"].get("remediation", "") \
                or "sshd_config" in ev["_finding"]["remediation"]


def test_ssh_rules_silent_on_strong_server(fake_ssh):
    host, port = fake_ssh(STRONG)
    res = sshcheck.check_ssh_algorithms(host, port)
    ctx = _ctx_with(res)
    for r in ssh_rules.RULES:
        assert r["match"](ctx) is None, r["id"]


def test_ssh_check_handles_closed_port():
    res = sshcheck.check_ssh_algorithms("127.0.0.1", 59999, timeout=1.0)
    assert "error" in res


def test_ssh_check_handles_non_ssh_service():
    # An HTTP-ish socket that never speaks SSH -> graceful error, no hang.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    srv.settimeout(10)

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(10)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")

    threading.Thread(target=serve, daemon=True).start()
    res = sshcheck.check_ssh_algorithms("127.0.0.1", port, timeout=3.0)
    srv.close()
    assert "error" in res
