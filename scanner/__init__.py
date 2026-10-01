"""Network scanning code lives here.

scanner/targets.py       -> parse + validate user targets (IP / CIDR / hostname)
scanner/reachability.py  -> quick host-discovery checks (Phase 1 of a scan)
scanner/portscan.py      -> TCP connect port scan, bounded thread pool (Phase 2)
scanner/fingerprint.py   -> service identification with confidence (Phase 3)
scanner/engine.py        -> orchestrates the full pipeline on a worker thread
scanner/jobs.py          -> background job start / cancel / crash recovery
"""
