# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Host reachability checks — the first REAL network operation in NetVulnX.

For each host we attempt a TCP connection to each requested port and record:
  - did the connection succeed?  (host is reachable / port is open)
  - how long did it take?        (latency in milliseconds)
  - if not, WHY not?             (refused vs. timed out — different meanings!)

A refused or timed-out connection is NOT an error — it is a RESULT.
Only unexpected failures are errors, and even those are recorded, never crash.

We use plain TCP connects (no raw packets): no special permissions needed,
and it is the gentlest possible probe of a host.
"""
import socket
import time


def check_port(ip: str, port: int, timeout: float = 2.0) -> dict:
    """Try ONE TCP connection. Returns a result dict — never raises."""
    started = time.monotonic()
    result = {"port": port, "open": False, "latency_ms": None, "note": ""}
    try:
        # create_connection() performs the TCP handshake, then the
        # 'with' block guarantees the socket is closed immediately.
        with socket.create_connection((ip, port), timeout=timeout):
            result["open"] = True
            result["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
            result["note"] = "TCP connect succeeded"
    except socket.timeout:
        result["note"] = f"No response within {timeout}s (filtered or host down)"
    except ConnectionRefusedError:
        result["note"] = "Connection refused (host is up, port is closed)"
    except OSError as exc:
        # Network unreachable, etc. — record it, don't crash.
        result["note"] = f"Network error: {exc.strerror or exc}"
    return result


def check_host(ip: str, ports: list, timeout: float = 2.0,
               progress_cb=None) -> dict:
    """Check one host across several ports, SEQUENTIALLY.

    Sequential (one connection at a time) is slower than parallel, but it is
    trivially safe: it cannot overwhelm the target. Bounded parallelism
    arrives in Milestone 2, when full port scans make it necessary.
    """
    port_results = []
    for i, port in enumerate(ports):
        port_results.append(check_port(ip, port, timeout))
        if progress_cb:
            progress_cb(i + 1, len(ports))  # lets callers show real progress

    open_ports = [r["port"] for r in port_results if r["open"]]
    latencies = [r["latency_ms"] for r in port_results if r["latency_ms"] is not None]
    return {
        "ip": ip,
        "reachable": bool(open_ports),   # reachable == at least one port answered
        "open_ports": open_ports,
        "latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "ports": port_results,           # full per-port detail (evidence)
    }
