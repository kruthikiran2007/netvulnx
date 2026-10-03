"""Tests for scanner/fingerprint.py.

Fake protocol servers run in-process on 127.0.0.1. Each test asserts not just
the identified service but the CONFIDENCE — the honesty contract of this module.
"""
import shutil
import socketserver
import threading
import time

import pytest

from scanner import fingerprint


needs_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="openssl CLI not installed (needed to generate test certificates)")


def _serve(handler_cls, banner=None):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class _SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        time.sleep(0.5)


class _FTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"220 (vsFTPd 3.0.3)\r\n")
        time.sleep(0.5)


class _HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # HTTP servers don't greet: only answer if the client actually spoke
        # (our active HEAD probe). Stay silent otherwise, so the test
        # deterministically exercises the ACTIVE probe path, not the banner.
        self.request.settimeout(1.0)
        try:
            data = self.request.recv(1024)
        except OSError:
            data = b""
        if data:
            self.request.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Server: TestServer/1.2.3\r\n"
                                 b"Content-Length: 0\r\n\r\n")
        time.sleep(0.2)


class _SilentHandler(socketserver.BaseRequestHandler):
    """Accepts and immediately closes: open port, zero protocol evidence."""
    def handle(self):
        pass


class _GarbageHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"\xff\x00not-a-protocol\r\n")
        time.sleep(0.3)


def _port(srv):
    return srv.server_address[1]


def test_ssh_banner_identified_with_high_confidence():
    srv = _serve(_SSHHandler)
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert fp["service"] == "ssh"
        assert fp["product"] == "OpenSSH"
        assert fp["version"] == "8.9p1"
        assert fp["confidence"] >= 90
        assert "SSH-2.0" in fp["banner"]
    finally:
        srv.shutdown()


def test_ftp_greeting_identified():
    srv = _serve(_FTPHandler)
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert fp["service"] == "ftp"
        assert fp["product"] == "vsftpd"
        assert fp["version"] == "3.0.3"
        assert fp["confidence"] >= 85
    finally:
        srv.shutdown()


def test_http_identified_via_active_probe():
    srv = _serve(_HTTPHandler)
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert fp["service"] == "http"
        assert fp["product"] == "TestServer"
        assert fp["version"] == "1.2.3"
        assert fp["confidence"] >= 75
        assert "active probe" in fp["method"]
    finally:
        srv.shutdown()


def test_unknown_service_gets_low_confidence_not_a_guess():
    srv = _serve(_GarbageHandler)
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert fp["service"] == "unknown"
        assert fp["confidence"] <= 25
        assert fp["product"] is None
    finally:
        srv.shutdown()


def test_port_hint_used_only_as_labeled_fallback(monkeypatch):
    # Silent server (open port, zero protocol evidence) on a port we
    # temporarily register a hint for -> must return the hint with LOW
    # confidence, explicitly labeled unverified.
    srv = socketserver.TCPServer(("127.0.0.1", 0), _SilentHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        monkeypatch.setitem(fingerprint._PORT_HINTS, port, "fakesvc")
        fp = fingerprint.fingerprint("127.0.0.1", port, timeout=1.0)
        assert fp["service"] == "fakesvc"
        assert fp["confidence"] < 60
        assert "unverified" in fp["method"]
    finally:
        srv.shutdown()


def test_banner_truncated_for_storage():
    long_banner = b"SSH-2.0-" + b"A" * 5000 + b"\r\n"

    class _LongHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(long_banner)
            time.sleep(0.3)

    srv = _serve(_LongHandler)
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert len(fp["banner"]) <= fingerprint.BANNER_MAX
        assert fp["service"] == "ssh"  # still identified despite truncation
    finally:
        srv.shutdown()


@needs_openssl
def test_tls_service_detected_via_handshake(tmp_path):
    """A TLS service on a non-standard port answers no plaintext probe;
    fingerprinting should still identify it via one real handshake."""
    import ssl
    import subprocess

    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(cert), "-days", "2", "-nodes",
        "-subj", "/CN=fp-test", "-addext", "subjectAltName=IP:127.0.0.1",
    ], check=True, capture_output=True)

    class _TLSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.recv(1024)
            except OSError:
                pass

    class _TLSServer(socketserver.TCPServer):
        allow_reuse_address = True

        def get_request(self):
            sock, addr = super().get_request()
            return self._ctx.wrap_socket(sock, server_side=True), addr

    srv = _TLSServer(("127.0.0.1", 0), _TLSHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv._ctx = ctx
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert fp["service"] == "https", fp
        assert fp["confidence"] >= 85
        assert "TLS handshake" in fp["method"]
        assert "fp-test" in fp["banner"]
    finally:
        srv.shutdown()


def test_smtp_banner_not_misidentified_as_ftp():
    """Regression: SMTP also greets with 220 — the FTP parser must yield."""

    class _SMTPBanner(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"220 fake.mail ESMTP Postfix 3.7.2\r\n")
            time.sleep(0.3)

    srv = _serve(_SMTPBanner)
    try:
        fp = fingerprint.fingerprint("127.0.0.1", _port(srv))
        assert fp["service"] == "smtp", fp
        assert fp["product"] == "Postfix"
    finally:
        srv.shutdown()
