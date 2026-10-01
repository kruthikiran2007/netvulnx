"""Web pages and actions.

A "blueprint" is Flask's way of grouping related pages together.
Each function below handles one URL (the @bp.get / @bp.post line above it
says which URL and which HTTP method).

Milestone-2 note: scans now run on BACKGROUND threads (scanner/jobs.py),
so the authorize POST returns immediately and the detail page polls
GET /api/scans/<id>/status for live progress.
"""
import math
from datetime import datetime, timezone

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, current_app, jsonify)

from app import db
from app.models import Scan, Asset, Port, Finding
from rules import SEVERITY_RANK
from rules.scoring import FORMULA_TEXT
from scanner import jobs
from scanner.targets import parse_target, parse_ports, TargetError
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
        total_open_ports=Port.query.count(),
        completed_scans=Scan.query.filter_by(status="completed").count(),
        recent_scans=scans[:5],
    )


@bp.get("/scans")
def scan_list():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("scans.html", scans=scans)


@bp.get("/scans/new")
def new_scan_form():
    return render_template("new_scan.html",
                           default_ports=Config.DEFAULT_PORTS,
                           profiles=Config.SCAN_PROFILES)


def _resolve_ports(profile: str, ports_text: str) -> list:
    """Turn a profile choice (+ optional custom port text) into a port list."""
    if profile == "custom":
        return parse_ports(ports_text, default=Config.DEFAULT_PORTS)
    return list(Config.SCAN_PROFILES[profile]["ports"])


@bp.post("/scans/new")
def new_scan_submit():
    """Step 1 of scan creation: validate target + profile.

    If anything is invalid, we go BACK to the form with a human-readable
    message — the scan is never created, nothing touches the network.
    """
    target_text = request.form.get("target", "")
    ports_text = request.form.get("ports", "")
    name = request.form.get("name", "").strip() or "Untitled scan"
    profile = request.form.get("profile", "quick")
    if profile not in Config.SCAN_PROFILES:
        profile = "quick"
    try:
        target = parse_target(target_text, allow_public=Config.ALLOW_PUBLIC_TARGETS)
        ports = _resolve_ports(profile, ports_text)
    except TargetError as exc:
        flash(str(exc), "error")
        return render_template("new_scan.html",
                               default_ports=Config.DEFAULT_PORTS,
                               profiles=Config.SCAN_PROFILES,
                               target=target_text, ports=ports_text,
                               name=name, profile=profile), 400

    scan = Scan(name=name,
                target_raw=target_text,
                target_type=target["type"],
                ports_raw=",".join(map(str, ports)),
                profile=profile,
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
    profile = Config.SCAN_PROFILES.get(scan.profile or "custom",
                                       Config.SCAN_PROFILES["custom"])
    # Honest worst-case estimate: every probe hits its full timeout, and the
    # thread pool processes SCAN_WORKERS probes at a time.
    probes = len(target["hosts"]) * len(ports)
    est_max = math.ceil(probes / Config.SCAN_WORKERS) * Config.PORT_TIMEOUT
    est_max += len(target["hosts"]) * 3  # discovery + fingerprinting overhead
    return render_template("authorize.html", scan=scan, target=target,
                           ports=ports, profile=profile,
                           est_max=int(est_max))


@bp.post("/scans/<int:scan_id>/authorize")
def authorize_scan_submit(scan_id):
    """THE SAFETY GATE: nothing touches the network until the user confirms.

    On confirmation the scan starts on a BACKGROUND thread and this request
    returns immediately — the detail page polls for live progress.
    """
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
    scan.current_stage = "Starting…"
    db.session.commit()

    jobs.start_scan_job(current_app._get_current_object(), scan.id)
    flash("Scan started in the background — progress is live below.", "info")
    return redirect(url_for("main.scan_detail", scan_id=scan.id))


@bp.post("/scans/<int:scan_id>/cancel")
def cancel_scan(scan_id):
    """Ask a running scan to stop. The worker checks between phases/chunks."""
    scan = Scan.query.get_or_404(scan_id)
    if scan.status == "running" and jobs.cancel_scan_job(scan.id):
        flash("Cancellation requested — the scan will stop shortly.", "info")
    else:
        flash("That scan is not running.", "error")
    return redirect(url_for("main.scan_detail", scan_id=scan.id))


@bp.get("/api/scans/<int:scan_id>/status")
def scan_status(scan_id):
    """Tiny JSON endpoint for the live progress poller. Real numbers only."""
    scan = Scan.query.get_or_404(scan_id)
    open_ports = sum(len(a.ports) for a in scan.assets)
    return jsonify({
        "status": scan.status,
        "progress": scan.progress,
        "stage": scan.current_stage or "",
        "assets": len(scan.assets),
        "open_ports": open_ports,
        "error": scan.error,
    })


@bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    findings = (Finding.query.filter_by(scan_id=scan_id).all())
    # Most severe first; stable order within a severity.
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id))
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    return render_template("scan_detail.html", scan=scan, findings=findings,
                           sev_counts=sev_counts, formula_text=FORMULA_TEXT)
