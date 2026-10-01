"""Scan orchestrator — runs the full assessment pipeline for one scan.

Pipeline per host:
    1. Host discovery  (quick "is anything there?" via reachability)
    2. Port scan       (bounded thread-pool connect scan)
    3. Fingerprinting  (banner grab + protocol parsers on open ports)
    4. Storage         (Asset + Port rows, real progress updates)

Runs on a background thread (see scanner/jobs.py). Progress is REAL:
hosts completed / total hosts, with per-host detail in current_stage.

Safety properties:
  - checks the cancel event between every phase and chunk
  - never leaves a scan stuck in "running" (try/except/finally)
  - commits per host, so a crash keeps partial results instead of nothing
"""
from datetime import datetime, timezone

from app import db
from app.models import Scan, Asset, Port
from scanner import jobs, reachability, portscan, fingerprint
from scanner.targets import parse_target, parse_ports
from config import Config


def _utcnow():
    return datetime.now(timezone.utc)


def run_scan(app, scan_id: int, cancel_event):
    """Thread entry point. Wraps _run with app context + guaranteed cleanup."""
    with app.app_context():
        try:
            _run(scan_id, cancel_event)
        except Exception as exc:  # last resort: record failure, never hang
            scan = db.session.get(Scan, scan_id)
            if scan is not None and scan.status == "running":
                scan.status = "failed"
                scan.error = f"{type(exc).__name__}: {exc}"
                db.session.commit()
        finally:
            jobs._finish_job(scan_id)


def _cancelled(scan, cancel_event) -> bool:
    if cancel_event.is_set():
        scan.status = "cancelled"
        scan.current_stage = "Cancelled by user"
        scan.completed_at = _utcnow()
        db.session.commit()
        return True
    return False


def _run(scan_id: int, cancel_event):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.status != "running":
        return

    profile = scan.profile or "custom"
    profile_cfg = Config.SCAN_PROFILES.get(profile, Config.SCAN_PROFILES["custom"])
    ports = parse_ports(scan.ports_raw)  # validated at creation; re-parse cheaply
    target = parse_target(scan.target_raw,
                          allow_public=Config.ALLOW_PUBLIC_TARGETS)
    hosts = target["hosts"]
    total_hosts = len(hosts)

    # Custom scans honor the user's exact port choice: if they asked for
    # port 8080, we check port 8080 — no discovery shortcut may skip it.
    # Quick/Standard use discovery to skip silent hosts quickly; Deep scans
    # everything (that's the point of Deep).
    do_discovery = profile_cfg.get("discovery", True) and profile != "custom"

    scan.started_at = _utcnow()
    db.session.commit()

    for i, ip in enumerate(hosts):
        if _cancelled(scan, cancel_event):
            return

        # ---- Phase 1: host discovery ----
        asset = Asset(scan_id=scan.id, ip_address=ip)
        if do_discovery:
            scan.current_stage = f"Host discovery: {ip} ({i + 1}/{total_hosts})"
            db.session.commit()
            disc = reachability.check_host(
                ip, [80, 443, 22], timeout=Config.DISCOVERY_TIMEOUT)
            asset.is_reachable = disc["reachable"]
            asset.latency_ms = disc["latency_ms"]
            if not disc["reachable"]:
                # Silent on the common ports: skip the full port scan for
                # speed. (Deep profile never takes this shortcut.)
                db.session.add(asset)
                db.session.commit()
                scan.progress = int((i + 1) / total_hosts * 100)
                db.session.commit()
                continue
        else:
            asset.is_reachable = True  # determined by the port scan itself

        # ---- Phase 2: port scan ----
        def on_progress(done, total):
            scan.current_stage = (f"Port scan {ip}: {done}/{total} "
                                  f"({i + 1}/{total_hosts} hosts)")
            # Commit periodically so the UI shows live progress.
            db.session.commit()

        scan.current_stage = f"Port scan: {ip} ({i + 1}/{total_hosts})"
        db.session.commit()
        result = portscan.scan_ports(
            ip, ports,
            timeout=Config.PORT_TIMEOUT,
            max_workers=Config.SCAN_WORKERS,
            cancel_event=cancel_event,
            progress_cb=on_progress)

        if _cancelled(scan, cancel_event):
            return

        # ---- Phase 3: fingerprint open ports ----
        open_ports = result["open"]
        asset.is_reachable = bool(open_ports) or asset.is_reachable
        db.session.add(asset)
        db.session.flush()  # assign asset.id for the Port rows below

        for j, port in enumerate(open_ports):
            if _cancelled(scan, cancel_event):
                return
            scan.current_stage = (f"Fingerprinting {ip}:{port} "
                                  f"({j + 1}/{len(open_ports)})")
            fp = fingerprint.fingerprint(ip, port,
                                         timeout=Config.BANNER_TIMEOUT)
            db.session.add(Port(
                scan_id=scan.id,
                asset_id=asset.id,
                port=port,
                protocol="tcp",
                state="open",
                service=fp["service"],
                confidence=fp["confidence"],
                product=fp["product"],
                version=fp["version"],
                banner=fp["banner"],
                method=fp["method"],
            ))

        # ---- Phase 4: commit this host, advance real progress ----
        scan.progress = int((i + 1) / total_hosts * 100)
        db.session.commit()

    scan.progress = 100
    scan.status = "completed"
    scan.current_stage = "Done"
    scan.completed_at = _utcnow()
    db.session.commit()
