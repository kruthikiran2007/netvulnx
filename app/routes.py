"""Web pages and actions.

A "blueprint" is Flask's way of grouping related pages together.
Each function below handles one URL (the @bp.get / @bp.post line above it
says which URL and which HTTP method).
"""
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash

from app import db
from app.models import Scan, Asset
from scanner.targets import parse_target, parse_ports, TargetError
from scanner.reachability import check_host
from config import Config

bp = Blueprint("main", __name__)


@bp.get("/")
def dashboard():
    """Home page. Every number comes from the database — nothing is hardcoded."""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template(
        "dashboard.html",
        total_scans=len(scans),
        total_assets=Asset.query.count(),
        completed_scans=Scan.query.filter_by(status="completed").count(),
        recent_scans=scans[:5],
    )


@bp.get("/scans")
def scan_list():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("scans.html", scans=scans)


@bp.get("/scans/new")
def new_scan_form():
    return render_template("new_scan.html", default_ports=Config.DEFAULT_PORTS)


@bp.post("/scans/new")
def new_scan_submit():
    """Step 1 of scan creation: validate the target.

    If anything is invalid, we go BACK to the form with a human-readable
    message — the scan is never created, nothing touches the network.
    """
    target_text = request.form.get("target", "")
    ports_text = request.form.get("ports", "")
    name = request.form.get("name", "").strip() or "Untitled scan"
    try:
        target = parse_target(target_text, allow_public=Config.ALLOW_PUBLIC_TARGETS)
        ports = parse_ports(ports_text, default=Config.DEFAULT_PORTS)
    except TargetError as exc:
        flash(str(exc), "error")
        return render_template("new_scan.html", default_ports=Config.DEFAULT_PORTS,
                               target=target_text, ports=ports_text, name=name), 400

    scan = Scan(name=name,
                target_raw=target_text,
                target_type=target["type"],
                ports_raw=",".join(map(str, ports)),
                status="awaiting_authorization")
    db.session.add(scan)
    db.session.commit()
    # Step 2 (next page): the authorization gate.
    return redirect(url_for("main.authorize_scan", scan_id=scan.id))


@bp.get("/scans/<int:scan_id>/authorize")
def authorize_scan(scan_id):
    """Show EXACTLY what will be scanned, and require explicit confirmation."""
    scan = Scan.query.get_or_404(scan_id)
    target = parse_target(scan.target_raw, allow_public=Config.ALLOW_PUBLIC_TARGETS)
    ports = parse_ports(scan.ports_raw)
    # Honest worst-case estimate: every host x every port x full timeout.
    est_max = len(target["hosts"]) * len(ports) * Config.CONNECT_TIMEOUT
    return render_template("authorize.html", scan=scan, target=target,
                           ports=ports, est_max=int(est_max),
                           timeout=Config.CONNECT_TIMEOUT)


@bp.post("/scans/<int:scan_id>/authorize")
def authorize_scan_submit(scan_id):
    """THE SAFETY GATE: nothing touches the network until the user confirms."""
    scan = Scan.query.get_or_404(scan_id)
    if scan.status != "awaiting_authorization":
        flash("This scan was already handled.", "error")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))

    if request.form.get("confirm") != "yes":
        # User declined (or bypassed the checkbox): cancel cleanly.
        scan.status = "cancelled"
        db.session.commit()
        flash("Scan cancelled — nothing was sent to the target.", "info")
        return redirect(url_for("main.scan_list"))

    scan.authorized = True
    scan.authorized_at = datetime.now(timezone.utc)
    scan.status = "running"
    scan.started_at = scan.authorized_at
    scan.current_stage = "Reachability check"
    db.session.commit()

    _run_reachability_scan(scan)

    return redirect(url_for("main.scan_detail", scan_id=scan.id))


def _run_reachability_scan(scan: Scan):
    """Milestone-1 scan: TCP reachability across the requested ports.

    Runs synchronously (the browser waits) because a few ports on a /24 or
    smaller finish in seconds. Background jobs arrive in Milestone 2, when
    full port scans make waiting impractical.
    """
    try:
        target = parse_target(scan.target_raw, allow_public=Config.ALLOW_PUBLIC_TARGETS)
        ports = parse_ports(scan.ports_raw)
        hosts = target["hosts"]
        total = len(hosts)

        for i, ip in enumerate(hosts):
            # Real progress: hosts finished / total hosts.
            scan.current_stage = f"Checking {ip} ({i + 1}/{total})"
            scan.progress = int(i / total * 100)
            db.session.commit()

            result = check_host(ip, ports, timeout=Config.CONNECT_TIMEOUT)
            db.session.add(Asset(
                scan_id=scan.id,
                ip_address=ip,
                is_reachable=result["reachable"],
                latency_ms=result["latency_ms"],
                open_ports_observed=",".join(map(str, result["open_ports"])),
            ))

        scan.progress = 100
        scan.status = "completed"
        scan.current_stage = "Done"
        scan.completed_at = datetime.now(timezone.utc)
    except Exception as exc:  # never leave a scan stuck in "running"
        scan.status = "failed"
        scan.error = f"{type(exc).__name__}: {exc}"
    db.session.commit()


@bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template("scan_detail.html", scan=scan)
