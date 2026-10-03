# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for the database greeting checks (Milestone 21).

Fake MySQL / PostgreSQL / Redis servers speak the real wire protocol so
the tests exercise the actual parsing — no mocks of the check functions.
"""
import json
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from scanner import dbcheck
from rules import db_rules


def _serve(handler):
    """Run handler(conn) for one connection on an ephemeral port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(10)
            try:
                handler(conn)
            except OSError:
                pass
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# Fake servers
# --------------------------------------------------------------------------
def _mysql_handshake(version):
    payload = b"\x0a" + version.encode() + b"\x00" + b"\x01" * 40
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


def _fake_mysql(version):
    def handler(conn):
        conn.sendall(_mysql_handshake(version))
        # Client would normally reply; just hold the socket briefly.
        try:
            conn.recv(1024)
        except OSError:
            pass
    return _serve(handler)


def _fake_postgres(ssl_ok):
    def handler(conn):
        req = _read_exact(conn, 8)
        assert struct.unpack(">II", req) == (8, 80877103)
        conn.sendall(b"S" if ssl_ok else b"N")
    return _serve(handler)


def _fake_redis(mode):
    def handler(conn):
        buf = b""
        while not buf.endswith(b"\r\n"):
            buf += conn.recv(1)
        assert buf == b"PING\r\n"
        if mode == "open":
            conn.sendall(b"+PONG\r\n")
        else:
            conn.sendall(b"-NOAUTH Authentication required.\r\n")
    return _serve(handler)


def _rule_ctx(check_type, details):
    row = SimpleNamespace(details=json.dumps(details))
    return {"checks": {check_type: row}}


# --------------------------------------------------------------------------
# MySQL
# --------------------------------------------------------------------------
def test_mysql_reads_version():
    port = _fake_mysql("8.0.36")
    res = dbcheck.check_mysql("127.0.0.1", port)
    assert res["server_version"] == "8.0.36"
    assert res["is_mariadb"] is False
    assert "error" not in res


def test_mysql_mariadb_flag():
    port = _fake_mysql("10.11.7-MariaDB-1:10.11.7+maria~ubu2204")
    res = dbcheck.check_mysql("127.0.0.1", port)
    assert res["is_mariadb"] is True


def test_mysql_eol_57_high():
    ctx = _rule_ctx("mysql_greeting", {"server_version": "5.7.44"})
    ev = db_rules._match_mysql_eol(ctx)
    assert ev["_finding"]["severity"] == "high"
    assert "5.7.44" in ev["_finding"]["title"]


def test_mysql_eol_80_medium():
    ctx = _rule_ctx("mysql_greeting", {"server_version": "8.0.36"})
    ev = db_rules._match_mysql_eol(ctx)
    assert ev["_finding"]["severity"] == "medium"


def test_mysql_supported_no_finding():
    ctx = _rule_ctx("mysql_greeting", {"server_version": "9.1.0"})
    assert db_rules._match_mysql_eol(ctx) is None


def test_mariadb_eol():
    ctx = _rule_ctx("mysql_greeting", {"server_version": "10.5.23-MariaDB"})
    ev = db_rules._match_mysql_eol(ctx)
    assert ev["_finding"]["severity"] == "high"
    ctx = _rule_ctx("mysql_greeting", {"server_version": "10.11.7-MariaDB"})
    assert db_rules._match_mysql_eol(ctx) is None


def test_mysql_closed_port():
    res = dbcheck.check_mysql("127.0.0.1", 1)
    assert "error" in res


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------
def test_postgres_ssl_offered():
    port = _fake_postgres(ssl_ok=True)
    res = dbcheck.check_postgres("127.0.0.1", port)
    assert res["ssl_supported"] is True
    ctx = _rule_ctx("postgres_ssl", res)
    assert db_rules._match_postgres_no_ssl(ctx) is None


def test_postgres_no_ssl_finding():
    port = _fake_postgres(ssl_ok=False)
    res = dbcheck.check_postgres("127.0.0.1", port)
    assert res["ssl_supported"] is False
    ctx = _rule_ctx("postgres_ssl", res)
    ev = db_rules._match_postgres_no_ssl(ctx)
    assert ev["_finding"]["severity"] == "medium"


# --------------------------------------------------------------------------
# Redis
# --------------------------------------------------------------------------
def test_redis_open_high():
    port = _fake_redis("open")
    res = dbcheck.check_redis("127.0.0.1", port)
    assert res["auth_required"] is False
    ctx = _rule_ctx("redis_ping", res)
    ev = db_rules._match_redis_no_auth(ctx)
    assert ev["_finding"]["severity"] == "high"


def test_redis_auth_required_no_finding():
    port = _fake_redis("locked")
    res = dbcheck.check_redis("127.0.0.1", port)
    assert res["auth_required"] is True
    ctx = _rule_ctx("redis_ping", res)
    assert db_rules._match_redis_no_auth(ctx) is None


def test_db_rules_registered():
    ids = [r["id"] for r in db_rules.RULES]
    assert ids == ["mysql-eol-version", "postgres-ssl-not-supported",
                   "redis-no-auth"]
