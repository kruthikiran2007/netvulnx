# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for the NoSQL / search-engine checks (Milestone 22).

Fake MongoDB / Elasticsearch / Memcached servers speak the real wire
protocols. The MongoDB fake's BSON replies are hand-assembled byte by
byte (not via the module's own builders) so the client's BSON parser is
genuinely exercised.
"""
import json
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from scanner import nosqlcheck
from rules import nosql_rules


def _serve(handler):
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


def _ctx(check_type, details):
    row = SimpleNamespace(details=json.dumps(details))
    return {"checks": {check_type: row}}


# --------------------------------------------------------------------------
# MongoDB fake (hand-built BSON)
# --------------------------------------------------------------------------
def _bson_hello_reply():
    body = b""
    body += b"\x01" + b"ok\x00" + struct.pack("<d", 1.0)
    body += b"\x08" + b"isWritablePrimary\x00" + b"\x01"
    body += b"\x10" + b"maxBsonObjectSize\x00" + struct.pack("<i", 16777216)
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _bson_buildinfo_reply(version):
    body = b""
    body += b"\x01" + b"ok\x00" + struct.pack("<d", 1.0)
    s = version.encode() + b"\x00"
    body += b"\x02" + b"version\x00" + struct.pack("<i", len(s)) + s
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _op_msg(doc):
    section = b"\x00" + doc
    total = 16 + 4 + len(section)
    return (struct.pack("<iiii", total, 7, 0, 2013) +
            struct.pack("<I", 0) + section)


def _fake_mongo(version="5.0.28"):
    def handler(conn):
        for reply_doc in (_bson_hello_reply(), _bson_buildinfo_reply(version)):
            header = _read_exact(conn, 16)
            (length, _, _, opcode) = struct.unpack("<iiii", header)
            assert opcode == 2013, f"expected OP_MSG, got {opcode}"
            _read_exact(conn, length - 16)  # the command; we don't care
            conn.sendall(_op_msg(reply_doc))
    return _serve(handler)


def test_bson_roundtrip():
    doc = nosqlcheck._bson_doc([
        (0x10, "hello", nosqlcheck._bson_int32(1)),
        (0x02, "$db", nosqlcheck._bson_string("admin")),
        (0x08, "flag", b"\x01"),
    ])
    parsed, _ = nosqlcheck._bson_parse_doc(doc)
    assert parsed == {"hello": 1, "$db": "admin", "flag": True}


def test_mongodb_no_auth_and_version():
    port = _fake_mongo("5.0.28")
    res = nosqlcheck.check_mongodb("127.0.0.1", port)
    assert res["auth_required"] is False
    assert res["server_version"] == "5.0.28"
    assert res["is_writable_primary"] is True
    assert "error" not in res


def test_mongodb_rule_no_auth_high():
    ctx = _ctx("mongodb_hello", {"auth_required": False,
                                 "server_version": "7.0.14"})
    ev = nosql_rules._match_mongo_no_auth(ctx)
    assert ev["_finding"]["severity"] == "high"


def test_mongodb_rule_eol():
    ctx = _ctx("mongodb_hello", {"auth_required": False,
                                 "server_version": "5.0.28"})
    ev = nosql_rules._match_mongo_eol(ctx)
    assert ev["_finding"]["severity"] == "medium"
    ctx = _ctx("mongodb_hello", {"auth_required": False,
                                 "server_version": "8.0.4"})
    assert nosql_rules._match_mongo_eol(ctx) is None


# --------------------------------------------------------------------------
# Elasticsearch fake
# --------------------------------------------------------------------------
_ES_BANNER = {
    "name": "node-1", "cluster_name": "test",
    "version": {"number": "7.17.10"},
    "tagline": "You Know, for Search",
}


def _fake_es(auth=False):
    def handler(conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += conn.recv(1024)
        assert buf.startswith(b"GET / ")
        if auth:
            conn.sendall(b"HTTP/1.0 401 Unauthorized\r\n"
                         b'WWW-Authenticate: Basic realm="x"\r\n\r\n')
        else:
            body = json.dumps(_ES_BANNER).encode()
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    return _serve(handler)


def test_elasticsearch_open():
    port = _fake_es(auth=False)
    res = nosqlcheck.check_elasticsearch("127.0.0.1", port)
    assert res["auth_required"] is False
    assert res["server_version"] == "7.17.10"
    ctx = _ctx("elasticsearch_banner", res)
    ev = nosql_rules._match_es_no_auth(ctx)
    assert ev["_finding"]["severity"] == "high"
    ev = nosql_rules._match_es_old(ctx)
    assert ev["_finding"]["severity"] == "medium"


def test_elasticsearch_auth_no_finding():
    port = _fake_es(auth=True)
    res = nosqlcheck.check_elasticsearch("127.0.0.1", port)
    assert res["auth_required"] is True
    ctx = _ctx("elasticsearch_banner", res)
    assert nosql_rules._match_es_no_auth(ctx) is None


def test_elasticsearch_modern_no_eol():
    ctx = _ctx("elasticsearch_banner", {"auth_required": False,
                                        "server_version": "8.11.0"})
    assert nosql_rules._match_es_old(ctx) is None
    assert nosql_rules._match_es_no_auth(ctx)["_finding"]["severity"] == "high"


# --------------------------------------------------------------------------
# Memcached fake
# --------------------------------------------------------------------------
def _fake_memcached():
    def handler(conn):
        buf = b""
        while not buf.endswith(b"\r\n"):
            buf += conn.recv(1)
        assert buf == b"version\r\n"
        conn.sendall(b"VERSION 1.6.22\r\n")
    return _serve(handler)


def test_memcached_exposed():
    port = _fake_memcached()
    res = nosqlcheck.check_memcached("127.0.0.1", port)
    assert res["auth_required"] is False
    assert res["server_version"] == "1.6.22"
    ctx = _ctx("memcached_version", res)
    ev = nosql_rules._match_memcached(ctx)
    assert ev["_finding"]["severity"] == "high"
    assert "1.6.22" in ev["_finding"]["description"]


def test_nosql_rules_registered():
    ids = [r["id"] for r in nosql_rules.RULES]
    assert ids == ["mongodb-no-auth", "mongodb-eol-version",
                   "elasticsearch-no-auth", "elasticsearch-old-version",
                   "memcached-exposed"]
