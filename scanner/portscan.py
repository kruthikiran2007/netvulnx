"""TCP port scanner — the Milestone-2 scan engine.

How it works: for each port we attempt a TCP connection ("connect scan").
No raw packets, no special permissions — the same thing your web browser
does, just pointed at many ports.

Two deliberate design choices:

1. BOUNDED CONCURRENCY. We use a thread pool with a fixed maximum number
   of workers (config SCAN_WORKERS). At most that many connections are ever
   in flight, so the scanner cannot overwhelm the target or your own machine.
   (Network I/O releases Python's GIL, so threads genuinely run in parallel
   here — this is one of the cases where Python threads shine.)

2. HONEST PORT STATES. A port is not just "open" or "closed":
     open     -> TCP handshake completed (something is listening)
     closed   -> connection actively REFUSED (host is up, nothing there)
     filtered -> no response within the timeout (firewall drop / host down)
   The distinction matters: "filtered" means "we don't know", not "closed".

Cancellation: pass a threading.Event; the scan checks it between chunks
and stops promptly, reporting what it found so far.
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import islice


def _probe(ip: str, port: int, timeout: float) -> dict:
    """Probe ONE port. Returns a result dict — never raises."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"port": port, "state": "open",
                    "latency_ms": round((time.monotonic() - start) * 1000, 1)}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "latency_ms": None}
    except socket.timeout:
        return {"port": port, "state": "filtered", "latency_ms": None}
    except OSError as exc:
        # Network unreachable and friends: treat as filtered, keep the note.
        return {"port": port, "state": "filtered", "latency_ms": None,
                "note": str(exc.strerror or exc)}


def scan_ports(ip: str, ports: list, timeout: float = 1.0,
               max_workers: int = 32, cancel_event=None,
               progress_cb=None) -> dict:
    """Scan ports on one host with a bounded thread pool.

    Returns:
      {"ip": ip,
       "ports": {port: {"port", "state", "latency_ms", ...}, ...},
       "open": [sorted open ports],
       "counts": {"open": n, "closed": n, "filtered": n},
       "cancelled": True/False}
    """
    results = {}
    cancelled = False

    # Work in chunks so cancellation is checked regularly and progress
    # is reported steadily. Chunk = 2x workers keeps the pool saturated.
    chunk_size = max(1, max_workers * 2)
    it = iter(ports)

    with ThreadPoolExecutor(max_workers=max_workers,
                            thread_name_prefix="portscan") as ex:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            chunk = list(islice(it, chunk_size))
            if not chunk:
                break
            # ex.map preserves order, so results line up with chunk.
            for port, res in zip(chunk, ex.map(lambda p: _probe(ip, p, timeout), chunk)):
                results[port] = res
            if progress_cb:
                progress_cb(len(results), len(ports))

    # Any port we never got to (cancelled) is simply absent from results.
    open_ports = sorted(p for p, r in results.items() if r["state"] == "open")
    counts = {"open": 0, "closed": 0, "filtered": 0}
    for r in results.values():
        counts[r["state"]] = counts.get(r["state"], 0) + 1

    return {"ip": ip, "ports": results, "open": open_ports,
            "counts": counts, "cancelled": cancelled}
