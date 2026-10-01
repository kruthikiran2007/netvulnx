"""Tests for scanner/servicecheck.py.

Fake DNS/SMTP/FTP servers run in-process on 127.0.0.1. DNS wire-format
helpers are also tested against hand-built packets.
"""
import socketserver
import struct
import threading

from scanner import servicecheck


def _serve(handler_cls):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

def _dns_response(txid, question, txt=None, rcode=0):
    """Build a minimal DNS response: echo the question, one TXT answer."""
    flags = 0x8180 | rcode
    ancount = 1 if txt is not None else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, ancount, 0, 0)
    pkt = header + question
    if txt is not None:
        txt_bytes = txt.encode()
        rdata = struct.pack("B", len(txt_bytes)) + txt_bytes
        # name = pointer to the question at offset 12, then TXT/CH/ttl/rdlen
        pkt += struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 16, 3, 0,
                                                      len(rdata)) + rdata
    return pkt


class _DNSHandler(socketserver.BaseRequestHandler):
    mode = "answer"  # or "refused"

    def handle(self):
        self.request.settimeout(2.0)
        ln = self.request.recv(2)
        if len(ln) < 2:
            return
        (length,) = struct.unpack(">H", ln)
        query = self.request.recv(length)
        txid = struct.unpack(">H", query[:2])[0]
        question = query[12:]  # skip the 12-byte DNS header
        if self.mode == "refused":
            resp = _dns_response(txid, question, txt=None, rcode=5)
        else:
            resp = _dns_response(txid, question, txt="TestDNS 9.9")
        self.request.sendall(struct.pack(">H", len(resp)) + resp)


def test_dns_version_bind_answered():
    srv = _serve(_DNSHandler)
    try:
        r = servicecheck.check_dns_version("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["version"] == "TestDNS 9.9"
    assert "disclosed" in r["note"]


def test_dns_refused_is_reported_honestly():
    class _Refused(_DNSHandler):
        mode = "refused"

    srv = _serve(_Refused)
    try:
        r = servicecheck.check_dns_version("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["version"] is None
    assert "REFUSED" in r["note"]


def test_dns_query_builder_and_parser_roundtrip():
    txid, query = servicecheck._build_version_bind_query()
    assert b"version" in query and b"bind" in query
    resp = _dns_response(txid, query[12:], txt="RoundTrip 1.0")
    parsed = servicecheck._parse_dns_response(resp, txid)
    assert parsed["version"] == "RoundTrip 1.0"


def test_dns_parser_rejects_txid_mismatch():
    _txid, query = servicecheck._build_version_bind_query()
    resp = _dns_response(1234, query[12:], txt="x")
    parsed = servicecheck._parse_dns_response(resp, 9999)
    assert parsed["version"] is None
    assert "mismatch" in parsed["note"]


# --------------------------------------------------------------------------
# SMTP
# --------------------------------------------------------------------------

class _SMTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        f = self.request.makefile("r", encoding="utf-8", errors="replace")
        self.request.sendall(b"220 test.local ESMTP FakeMTA\r\n")
        for line in f:
            cmd = line.strip().upper()
            if cmd.startswith("EHLO"):
                self.request.sendall(b"250-test.local\r\n"
                                     b"250-STARTTLS\r\n"
                                     b"250 HELP\r\n")
            elif cmd == "QUIT":
                self.request.sendall(b"221 Bye\r\n")
                break


def test_smtp_ehlo_extensions_and_starttls():
    srv = _serve(_SMTPHandler)
    try:
        r = servicecheck.check_smtp("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["error"] is None
    assert "test.local" in r["banner"]
    assert "STARTTLS" in r["extensions"]
    assert r["starttls_advertised"] is True


# --------------------------------------------------------------------------
# FTP
# --------------------------------------------------------------------------

class _FTPHandler(socketserver.BaseRequestHandler):
    allow_anonymous = True

    def handle(self):
        f = self.request.makefile("r", encoding="utf-8", errors="replace")
        self.request.sendall(b"220 FakeFTPd ready\r\n")
        for line in f:
            cmd = line.strip().upper()
            if cmd.startswith("USER"):
                self.request.sendall(b"331 Password required\r\n")
            elif cmd.startswith("PASS"):
                if self.allow_anonymous:
                    self.request.sendall(b"230 Anonymous access granted\r\n")
                else:
                    self.request.sendall(b"530 Login incorrect\r\n")
            elif cmd == "QUIT":
                self.request.sendall(b"221 Goodbye\r\n")
                break


def test_ftp_anonymous_allowed_detected():
    srv = _serve(_FTPHandler)
    try:
        r = servicecheck.check_ftp_anonymous("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["error"] is None
    assert r["anonymous_allowed"] is True
    assert r["pass_response"] == 230
    assert "ALLOWED" in r["summary"]


def test_ftp_anonymous_denied_detected():
    class _Deny(_FTPHandler):
        allow_anonymous = False

    srv = _serve(_Deny)
    try:
        r = servicecheck.check_ftp_anonymous("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["anonymous_allowed"] is False
    assert r["pass_response"] == 530
