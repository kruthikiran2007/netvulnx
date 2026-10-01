"""Tests for scanner/portscan.py.

We spin up REAL tiny TCP servers on 127.0.0.1 (in-process, ephemeral ports)
so the scanner talks to something genuine. Loopback-only, no external traffic.
"""
import socket
import socketserver
import threading
import time

from scanner import portscan


class _QuietHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Hold the connection briefly, then close.
        time.sleep(0.3)


def _start_server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _QuietHandler)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _free_port():
    """A port that is (almost certainly) closed: bind, then release."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_open_port_detected():
    srv = _start_server()
    try:
        port = srv.server_address[1]
        res = portscan.scan_ports("127.0.0.1", [port], timeout=2.0, max_workers=4)
        assert res["ports"][port]["state"] == "open"
        assert res["open"] == [port]
        assert res["counts"]["open"] == 1
        assert res["cancelled"] is False
    finally:
        srv.shutdown()


def test_closed_port_detected_as_closed():
    srv = _start_server()
    port = srv.server_address[1]
    # shutdown() stops the serve loop; server_close() releases the socket,
    # so the port truly becomes "connection refused".
    srv.shutdown()
    srv.server_close()
    time.sleep(0.2)
    res = portscan.scan_ports("127.0.0.1", [port], timeout=2.0, max_workers=4)
    assert res["ports"][port]["state"] == "closed"


def test_mixed_ports_sorted_and_counted():
    srv = _start_server()
    try:
        open_port = srv.server_address[1]
        closed_port = _free_port()
        res = portscan.scan_ports("127.0.0.1", [closed_port, open_port],
                                  timeout=2.0, max_workers=4)
        assert res["open"] == [open_port]
        assert res["counts"]["open"] == 1
        assert res["counts"]["closed"] == 1
        assert res["ports"][open_port]["latency_ms"] is not None
    finally:
        srv.shutdown()


def test_filtered_port_on_timeout(monkeypatch):
    # "Filtered" = connect() neither succeeds nor refuses, it times out.
    # We simulate the timeout directly because this sandbox transparently
    # proxies outbound traffic, so no real address reliably times out here.
    # (The open/closed tests above cover the real network path.)
    import socket as _socket

    def _raise_timeout(*args, **kwargs):
        raise _socket.timeout("timed out")

    monkeypatch.setattr("socket.create_connection", _raise_timeout)
    res = portscan.scan_ports("127.0.0.1", [80], timeout=0.5, max_workers=2)
    assert res["ports"][80]["state"] == "filtered"
    assert res["open"] == []


def test_pre_cancelled_scan_returns_immediately():
    cancel = threading.Event()
    cancel.set()  # cancelled BEFORE starting
    start = time.monotonic()
    res = portscan.scan_ports("127.0.0.1", list(range(1, 51)),
                              timeout=1.0, max_workers=8,
                              cancel_event=cancel)
    elapsed = time.monotonic() - start
    assert res["cancelled"] is True
    assert res["ports"] == {}
    assert elapsed < 2.0  # did not actually scan anything


def test_progress_callback_reports_real_counts():
    srv = _start_server()
    try:
        port = srv.server_address[1]
        seen = []
        res = portscan.scan_ports("127.0.0.1", [port, _free_port()],
                                  timeout=2.0, max_workers=4,
                                  progress_cb=lambda done, total: seen.append((done, total)))
        assert seen, "callback was never called"
        assert seen[-1] == (2, 2)  # final report matches reality
        assert all(d <= t for d, t in seen)
    finally:
        srv.shutdown()
