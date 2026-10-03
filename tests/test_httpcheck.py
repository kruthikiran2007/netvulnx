# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for scanner/httpcheck.py.

Fake HTTP servers (raw sockets, full control over status/headers/body)
run in-process on 127.0.0.1.
"""
import socketserver
import threading

from scanner import httpcheck


class _Handler(socketserver.BaseRequestHandler):
    """Serves per-path canned responses; server.routes is a fn path->bytes."""
    def handle(self):
        self.request.settimeout(2.0)
        try:
            data = self.request.recv(4096)
        except OSError:
            return
        if not data:
            return
        path = data.split(b" ")[1].decode("latin1") if b" " in data else "/"
        self.request.sendall(self.server.routes(path))


def _serve(routes):
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    srv.routes = routes
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _resp(status, headers, body=b""):
    head = f"HTTP/1.1 {status}\r\n".encode()
    for k, v in headers.items():
        head += f"{k}: {v}\r\n".encode()
    head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
    return head + body


def test_redirect_chain_and_headers_recorded():
    def routes(path):
        if path == "/":
            return _resp("302 Found", {"Location": "/login"})
        body = b"<html><head><title>Welcome to nginx!</title></head></html>"
        return _resp("200 OK",
                     {"Server": "nginx/1.18.0",
                      "X-Content-Type-Options": "nosniff"},
                     body)
    srv = _serve(routes)
    try:
        r = httpcheck.analyze_http("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["error"] is None
    assert r["status_code"] == 200
    assert r["final_url"].endswith("/login")
    assert len(r["redirect_chain"]) == 2
    assert r["redirect_chain"][0]["status"] == 302
    assert r["redirect_chain"][0]["location"] == "/login"
    assert r["server_header"] == "nginx/1.18.0"
    assert r["security_headers"]["x-content-type-options"] == "nosniff"
    assert "CSP" in r["missing_security_headers"]
    assert "HSTS" in r["missing_security_headers"]
    assert r["default_page"] == "nginx default page"
    assert r["directory_listing"] is False
    assert r["redirects_to_https"] is False


def test_directory_listing_detected():
    body = b"<html><head><title>Index of /secret</title></head></html>"
    srv = _serve(lambda path: _resp("200 OK", {"Server": "Apache"}, body))
    try:
        r = httpcheck.analyze_http("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    assert r["error"] is None
    assert r["directory_listing"] is True
    assert r["page_title"] == "Index of /secret"


def test_https_upgrade_observed_even_when_follow_fails():
    port_holder = {}

    def routes(path):
        return _resp("301 Moved Permanently",
                     {"Location": f"https://127.0.0.1:{port_holder['p']}/"})

    srv = _serve(routes)
    port_holder["p"] = srv.server_address[1]
    try:
        r = httpcheck.analyze_http("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
    # Following the https:// hop fails (plain HTTP server) — honest error,
    # but the upgrade observation survives because the chain was recorded.
    assert r["error"] is not None
    assert r["redirects_to_https"] is True
    assert len(r["redirect_chain"]) == 1


def test_unreachable_port_returns_honest_error():
    srv = _serve(lambda path: b"")
    port = srv.server_address[1]
    srv.shutdown()
    r = httpcheck.analyze_http("127.0.0.1", port, timeout=1.0)
    assert r["error"] is not None
