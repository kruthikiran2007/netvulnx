"""Scan orchestrator — runs the full assessment pipeline for one scan.

Pipeline per host:
    1. Host discovery  (quick "is anything there?" via reachability)
    2. Port scan       (bounded thread-pool connect scan)
    3. Fingerprinting  (banner grab + protocol parsers on open ports)
    3b. Service analysis (TLS / HTTP / DNS / SMTP / FTP — read-only)
    3c. Rule evaluation (deterministic rules turn observations into findings)
    4. Storage         (Asset + Port + analysis rows + findings, real progress)

Runs on a background thread (see scanner/jobs.py). Progress is REAL:
hosts completed / total hosts, with per-host detail in current_stage.

Safety properties:
  - checks the cancel event between every phase and chunk
  - never leaves a scan stuck in "running" (try/except/finally)
  - commits per host, so a crash keeps partial results instead of nothing
  - rule evaluation is pure matching: a rule can never invent a finding,
    and a buggy rule is skipped instead of crashing the scan
"""
import json
from datetime import datetime, timezone

from app import db
from app.models import Scan, Asset, Port, TlsInfo, HttpInfo, ServiceCheck, Finding
from rules import evaluate as evaluate_rules
from rules.scoring import score_findings
from scanner import jobs, reachability, portscan, fingerprint
from scanner import tlscheck, httpcheck, servicecheck
from scanner import udpprobe, smbcheck, rdpcheck, dbcheck, authchecks, nosqlcheck
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


# Ports where we attempt TLS analysis even if fingerprinting couldn't
# confirm HTTPS (a TLS service won't answer our plaintext HTTP probe).
_TLS_PORTS = {443, 8443}
# Ports where we attempt plain HTTP analysis on an unidentified service.
_HTTP_PORTS = {80, 8080, 8000, 8888}


def _wants_tls(service: str, port: int) -> bool:
    return service == "https" or (port in _TLS_PORTS and service in ("unknown", "http"))


def _wants_http(service: str, port: int) -> bool:
    return service in ("http", "https") or (port in _HTTP_PORTS and service == "unknown")


def _analyze_service(scan, ip: str, port_num: int, service: str, port_row: Port,
                     cancel_event, auth_creds=None) -> bool:
    """Phase 3b: read-only TLS/HTTP/service checks for one open port.

    Returns False if cancelled mid-way (caller should stop the scan).
    Every check is time-boxed and read-only; failures are stored as
    errors on the row, never raised.
    """
    sni_name = scan.target_raw if scan.target_type == "hostname" else None

    if _wants_tls(service, port_num):
        if cancel_event.is_set():
            return False
        scan.current_stage = f"TLS analysis {ip}:{port_num}"
        db.session.commit()
        tls = tlscheck.analyze_tls(ip, port_num, timeout=Config.TLS_TIMEOUT,
                                   server_name=sni_name, check_name=ip)
        not_after = None
        if tls.get("cert_not_after"):
            not_after = datetime.fromisoformat(tls["cert_not_after"])
        db.session.add(TlsInfo(
            port_id=port_row.id,
            tls_version=tls.get("tls_version"),
            cipher_name=tls.get("cipher_name"),
            cipher_bits=tls.get("cipher_bits"),
            weak_cipher=tls.get("weak_cipher"),
            supports_tls10=tls.get("supports_tls10"),
            supports_tls11=tls.get("supports_tls11"),
            supports_tls12=tls.get("supports_tls12"),
            cert_subject=tls.get("cert_subject"),
            cert_issuer=tls.get("cert_issuer"),
            cert_sans=",".join(tls.get("cert_sans") or []),
            cert_not_after=not_after,
            cert_expired=tls.get("cert_expired"),
            cert_self_signed=tls.get("cert_self_signed"),
            hostname_mismatch=tls.get("hostname_mismatch"),
            error=tls.get("error"),
        ))

    if _wants_http(service, port_num):
        if cancel_event.is_set():
            return False
        scan.current_stage = f"HTTP analysis {ip}:{port_num}"
        db.session.commit()
        use_tls = service == "https" or port_num in _TLS_PORTS
        http = httpcheck.analyze_http(ip, port_num, use_tls=use_tls,
                                      timeout=Config.HTTP_TIMEOUT)
        db.session.add(HttpInfo(
            port_id=port_row.id,
            scheme="https" if use_tls else "http",
            final_url=http.get("final_url"),
            status_code=http.get("status_code"),
            redirect_chain=json.dumps(http.get("redirect_chain") or []),
            server_header=http.get("server_header"),
            powered_by=http.get("powered_by"),
            present_security_headers=json.dumps(http.get("security_headers") or {}),
            missing_security_headers=json.dumps(http.get("missing_security_headers") or []),
            redirects_to_https=http.get("redirects_to_https"),
            page_title=http.get("page_title"),
            directory_listing=http.get("directory_listing"),
            default_page=http.get("default_page"),
            error=http.get("error"),
        ))

    # Named service-specific checks: (service or port) -> (check_type, fn)
    extra_checks = []
    if service == "ftp" or port_num == 21:
        extra_checks.append(("ftp_anonymous", servicecheck.check_ftp_anonymous))
    if service == "smtp" or port_num in (25, 587):
        extra_checks.append(("smtp_ehlo", servicecheck.check_smtp))
    if service == "dns" or port_num == 53:
        extra_checks.append(("dns_version", servicecheck.check_dns_version))
    if service == "ssh" or port_num == 22:
        extra_checks.append(("ssh_algorithms", servicecheck.check_ssh_algorithms))
    if service == "smb" or port_num == 445:
        extra_checks.append(("smb_negotiate", smbcheck.check_smb))
    if service == "rdp" or port_num == 3389:
        extra_checks.append(("rdp_negotiate", rdpcheck.check_rdp))
    if service == "mysql" or port_num == 3306:
        extra_checks.append(("mysql_greeting", dbcheck.check_mysql))
    if service in ("postgresql", "postgres") or port_num == 5432:
        extra_checks.append(("postgres_ssl", dbcheck.check_postgres))
    if service == "redis" or port_num == 6379:
        extra_checks.append(("redis_ping", dbcheck.check_redis))
    if service == "mongodb" or port_num == 27017:
        extra_checks.append(("mongodb_hello", nosqlcheck.check_mongodb))
    if service == "elasticsearch" or port_num == 9200:
        extra_checks.append(("elasticsearch_banner",
                             nosqlcheck.check_elasticsearch))
    if service == "memcached" or port_num == 11211:
        extra_checks.append(("memcached_version",
                             nosqlcheck.check_memcached))

    # Authenticated checks (Milestone 21): credentials were supplied on the
    # authorization page and live only in the in-memory vault. They are
    # popped once at scan start (see _run) and never stored anywhere.
    if auth_creds and (service == "ssh" or port_num == 22):
        def _ssh_audit(h, p, timeout=Config.SERVICE_CHECK_TIMEOUT,
                       _c=auth_creds):
            return authchecks.check_ssh_config(
                h, p, _c["username"], _c["password"], timeout=timeout)
        extra_checks.append(("ssh_config_audit", _ssh_audit))

    for check_type, fn in extra_checks:
        if cancel_event.is_set():
            return False
        scan.current_stage = f"Service check {check_type} {ip}:{port_num}"
        db.session.commit()
        try:
            res = fn(ip, port_num, timeout=Config.SERVICE_CHECK_TIMEOUT)
        except Exception as exc:  # belt and braces: record, don't crash
            res = {"error": f"{type(exc).__name__}: {exc}"}
        summary = res.pop("summary", None) or res.get("note") or res.get("error") or "checked"
        db.session.add(ServiceCheck(
            port_id=port_row.id,
            check_type=check_type,
            summary=summary[:255],
            details=json.dumps(res, default=str),
        ))

    return True


def _evaluate_rules(scan, asset, port_row):
    """Phase 3c: run the deterministic rule engine for one port.

    The context is built only from measured observations (Port + TlsInfo +
    HttpInfo + ServiceCheck rows). Each matching rule contributes one Finding
    with its evidence; non-matching rules contribute nothing — this is where
    "no invented findings" is enforced.
    """
    ctx = {
        "target": scan.target_raw,
        "scan": scan,
        "asset": asset,
        "port": port_row,
        "tls": port_row.tls_info,
        "http": port_row.http_info,
        "checks": {c.check_type: c for c in port_row.service_checks},
    }
    for rule, evidence in evaluate_rules(ctx):
        # Dynamic findings (Milestones 9, 18): a rule may override the
        # static title/description/severity via evidence["_finding"], or
        # expand into several findings via evidence["_findings"] (each a
        # dict of the same override fields). The static rule text stays as
        # the schema fallback.
        for override in _dynamic_findings(evidence):
            db.session.add(Finding(
                scan_id=scan.id,
                asset_id=asset.id,
                port_id=port_row.id,
                rule_id=rule["id"],
                title=(override.get("title") if override else None)
                      or rule["title"],
                description=(override.get("description") if override else None)
                      or rule["description"],
                severity=(override.get("severity") if override else None)
                      or rule["severity"],
                confidence=rule["confidence"],
                evidence=json.dumps(evidence, default=str),
                impact=(override.get("impact") if override else None)
                      or rule["impact"],
                remediation=(override.get("remediation") if override else None)
                      or rule["remediation"],
                references=json.dumps(
                    (override.get("references") if override else None)
                    or rule.get("references", [])),
            ))


def _dynamic_findings(evidence):
    """Normalize dynamic-finding evidence into a list of override dicts.

    Returns [None] for the plain static case. Pops the control keys so the
    stored evidence stays clean.
    """
    multi = evidence.pop("_findings", None)
    if multi:
        return list(multi)
    single = evidence.pop("_finding", None)
    return [single]


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

    # Authenticated checks (Milestone 21): single-use pop from the
    # in-memory vault. The vault no longer holds them after this; the
    # local reference below is dropped when _run returns, and the
    # credentials are never written to the database or logs.
    auth_creds = authchecks.take_credentials(scan_id)

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
            port_row = Port(
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
            )
            db.session.add(port_row)
            db.session.flush()  # assign port_row.id for the analysis rows

            # ---- Phase 3b: read-only service analysis ----
            if not _analyze_service(scan, ip, port, fp["service"],
                                    port_row, cancel_event,
                                    auth_creds=auth_creds):
                _cancelled(scan, cancel_event)
                return

            # ---- Phase 3c: rule engine turns observations into findings ----
            if _cancelled(scan, cancel_event):
                return
            scan.current_stage = (f"Rule evaluation {ip}:{port} "
                                  f"({j + 1}/{len(open_ports)})")
            _evaluate_rules(scan, asset, port_row)
            db.session.commit()

        # ---- Phase 3d: UDP service discovery (Milestone 19) ----
        # Only confirmed responses are stored; silent ports are "open|filtered"
        # and recorded nowhere (silence is not evidence).
        udp_ports = Config.DEFAULT_UDP_PORTS
        for port in udp_ports:
            if _cancelled(scan, cancel_event):
                return
            scan.current_stage = f"UDP discovery {ip}:{port}/udp"
            db.session.commit()
            try:
                res = udpprobe.probe_udp(ip, port,
                                         timeout=Config.UDP_PROBE_TIMEOUT)
            except Exception as exc:  # belt and braces: record, don't crash
                res = {"port": port, "service": f"udp-{port}",
                       "state": "open|filtered", "details": {},
                       "error": f"{type(exc).__name__}: {exc}"}
            if res["state"] != "open":
                continue
            port_row = Port(
                scan_id=scan.id,
                asset_id=asset.id,
                port=port,
                protocol="udp",
                state="open",
                service=res["service"],
                confidence=90,  # well-formed protocol response
                banner=(res["details"].get("version")
                        or res["details"].get("sysDescr")
                        or res["service"])[:200],
                method="udp-probe",
            )
            db.session.add(port_row)
            db.session.flush()
            db.session.add(ServiceCheck(
                port_id=port_row.id,
                check_type="udp_probe",
                summary=f"UDP/{port} {res['service']} answered probe",
                details=json.dumps(res, default=str),
            ))
            db.session.flush()
            _evaluate_rules(scan, asset, port_row)
            db.session.commit()

        # ---- Phase 4: commit this host, advance real progress ----
        scan.progress = int((i + 1) / total_hosts * 100)
        db.session.commit()

    scan.progress = 100
    scan.status = "completed"
    scan.current_stage = "Done"
    scan.completed_at = _utcnow()
    # Aggregate risk score: a simple sum of severity weights — see
    # rules/scoring.py. Informational findings add nothing.
    scan.risk_score = score_findings(
        Finding.query.filter_by(scan_id=scan.id).all())
    db.session.commit()

    # Milestone 16: scheduled runs notify their webhook (best-effort).
    from scanner import notify as _notify
    _notify.notify_scan_completed(scan)
