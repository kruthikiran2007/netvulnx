"""Tests for scanner/tlscheck.py.

A real TLS server (self-signed cert generated with openssl) runs in-process
on 127.0.0.1. Pure parsing helpers are tested without any network.
"""
import socketserver
import ssl
import subprocess
import threading

import pytest

from scanner import tlscheck


def _make_cert(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(cert),
        "-days", "2", "-nodes",
        "-subj", "/CN=netvulnx-test",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)
    return str(cert), str(key)


class _TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(1024)
        except OSError:
            pass


class _TLSServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, certfile, keyfile):
        super().__init__(addr, handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        # Pin the floor explicitly: whether a "default" context allows
        # TLS 1.0 depends on the platform's OpenSSL security level
        # (Kali allows it, Ubuntu does not). The test's intent is a
        # modern, normally-configured server.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx = ctx

    def get_request(self):
        sock, addr = super().get_request()
        return self._ctx.wrap_socket(sock, server_side=True), addr


@pytest.fixture()
def tls_server(tmp_path):
    cert, key = _make_cert(tmp_path)
    srv = _TLSServer(("127.0.0.1", 0), _TLSHandler, cert, key)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def test_handshake_reports_version_cipher_and_cert(tls_server):
    port = tls_server.server_address[1]
    r = tlscheck.analyze_tls("127.0.0.1", port, check_name="127.0.0.1")
    assert r["error"] is None
    assert r["tls_version"].startswith("TLSv1")
    assert r["cipher_name"]
    assert r["cipher_bits"] >= 128
    assert r["weak_cipher"] is False
    assert r["cert_self_signed"] is True
    assert r["cert_expired"] is False
    assert "127.0.0.1" in r["cert_sans"]
    assert "netvulnx-test" in r["cert_subject"]
    assert r["hostname_mismatch"] is False


def test_old_protocols_refused_by_default_server(tls_server):
    port = tls_server.server_address[1]
    r = tlscheck.analyze_tls("127.0.0.1", port)
    assert r["error"] is None
    assert r["supports_tls10"] is False
    assert r["supports_tls11"] is False
    assert r["supports_tls12"] is True


def test_non_tls_port_returns_honest_error():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _TLSHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        r = tlscheck.analyze_tls("127.0.0.1", srv.server_address[1],
                                 timeout=2.0)
        assert r["error"] is not None
        assert "handshake failed" in r["error"]
    finally:
        srv.shutdown()


def test_weak_cipher_detection_is_deterministic():
    assert tlscheck.is_weak_cipher("ECDHE-RSA-DES-CBC3-SHA") is True
    assert tlscheck.is_weak_cipher("RC4-SHA") is True
    assert tlscheck.is_weak_cipher("TLS_AES_256_GCM_SHA384") is False
    assert tlscheck.is_weak_cipher("ECDHE-RSA-AES128-GCM-SHA256") is False


def test_hostname_matching():
    cert = {"subjectAltName": (("DNS", "*.example.com"), ("DNS", "example.com"))}
    assert tlscheck.hostname_matches(cert, "www.example.com") is True
    assert tlscheck.hostname_matches(cert, "example.com") is True
    assert tlscheck.hostname_matches(cert, "evil.com") is False
    # Wildcards only cover one level:
    assert tlscheck.hostname_matches(cert, "a.b.example.com") is False

    ip_cert = {"subjectAltName": (("IP Address", "10.0.0.5"),)}
    assert tlscheck.hostname_matches(ip_cert, "10.0.0.5") is True
    assert tlscheck.hostname_matches(ip_cert, "10.0.0.6") is False

    cn_cert = {"subject": ((("commonName", "legacy.local"),),)}
    assert tlscheck.hostname_matches(cn_cert, "legacy.local") is True
    assert tlscheck.hostname_matches({}, "anything") is None


def test_cert_time_parsing():
    dt = tlscheck._parse_cert_time("Oct  1 00:00:00 2026 GMT")
    assert (dt.year, dt.month, dt.day) == (2026, 10, 1)
    assert dt.tzinfo is not None
    assert tlscheck._parse_cert_time("not a date") is None
