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
                   flash, current_app, jsonify, abort)

from sqlalchemy import func

from app import db
from app.models import (Scan, Asset, Port, Finding, FINDING_STATUSES,
                        CLOSED_STATUSES)
from app.stats import (severity_counts, worst_severity, service_exposure,
                       inventory_rows, risk_history, recent_findings)
from app.diff import compare_findings, compare_ports, summarize
from rules import SEVERITY_RANK
from rules.scoring import FORMULA_TEXT
from scanner import jobs
from scanner.targets import parse_target, parse_ports, TargetError
from config import Config

bp = Blueprint("main", __name__)


def _open_finding_counts(scan_ids):
    """{scan_id: number of findings not yet closed} for remediation columns."""
    if not scan_ids:
        return {}
    rows = (db.session.query(Finding.scan_id, func.count(Finding.id))
            .filter(Finding.scan_id.in_(scan_ids),
                    ~Finding.status.in_(CLOSED_STATUSES))
            .group_by(Finding.scan_id).all())
    return dict(rows)


def _safe_back(fallback):
    """Redirect back to the referring page, but only inside our own app
    (never follow a Referer pointing elsewhere — open-redirect safety)."""
    ref = request.referrer or ""
    if ref.startswith(request.host_url):
        return redirect(ref)
    return redirect(fallback)


@bp.get("/")
def dashboard():
    """Home page. Every number comes from the database — nothing is hardcoded."""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    findings = Finding.query.all()
    return render_template(
        "dashboard.html",
        total_scans=len(scans),
        total_assets=Asset.query.count(),
        total_open_ports=Port.query.count(),
        completed_scans=Scan.query.filter_by(status="completed").count(),
        total_findings=len(findings),
        sev_counts=severity_counts(findings),
        risk_history=risk_history(scans),
        recent_findings=recent_findings(findings),
        recent_scans=scans[:5],
        open_counts=_open_finding_counts([s.id for s in scans]),
    )


@bp.get("/assets")
def asset_inventory():
    """Global asset inventory: one row per IP seen across all scans."""
    assets = Asset.query.order_by(Asset.checked_at.desc()).all()
    return render_template("assets.html", rows=inventory_rows(assets))


@bp.get("/assets/<path:ip>")
def asset_detail(ip):
    """Timeline of one IP across every scan that observed it, newest first."""
    assets = (Asset.query.filter_by(ip_address=ip)
              .order_by(Asset.checked_at.desc()).all())
    if not assets:
        abort(404)
    timeline = []
    for a in assets:
        port_rows = []
        for p in sorted(a.ports, key=lambda x: x.port):
            port_rows.append({
                "port": p.port,
                "service": p.service or "unknown",
                "worst": worst_severity(f.severity for f in p.findings),
            })
        findings = sorted(a.findings,
                          key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id))
        timeline.append({
            "scan_id": a.scan_id, "scan_name": a.scan.name,
            "status": a.scan.status, "hostname": a.hostname,
            "checked_at": a.checked_at, "latency_ms": a.latency_ms,
            "ports": port_rows, "findings": findings,
        })
    return render_template("asset_detail.html", ip=ip, timeline=timeline)


@bp.get("/attack-surface")
def attack_surface():
    """What is exposed, aggregated across completed scans.

    Only completed scans count: an interrupted scan's partial data would
    misrepresent the surface.
    """
    completed_ids = [s.id for s in Scan.query.filter_by(status="completed").all()]
    if completed_ids:
        ports = Port.query.filter(Port.scan_id.in_(completed_ids)).all()
        findings = Finding.query.filter(
            Finding.scan_id.in_(completed_ids)).all()
        assets = (Asset.query.filter(Asset.scan_id.in_(completed_ids))
                  .order_by(Asset.checked_at.desc()).all())
    else:
        ports, findings, assets = [], [], []

    exposure = service_exposure(ports)

    # Latest completed scan, for the per-asset surface view.
    latest = (Scan.query.filter_by(status="completed")
              .order_by(Scan.completed_at.desc()).first())
    surface = []
    if latest:
        for a in sorted(latest.assets, key=lambda x: x.ip_address):
            port_rows = []
            for p in sorted(a.ports, key=lambda x: x.port):
                port_rows.append({
                    "port": p.port,
                    "service": p.service or "unknown",
                    "worst": worst_severity(f.severity for f in p.findings),
                })
            surface.append({"ip": a.ip_address, "hostname": a.hostname,
                            "ports": port_rows})

    return render_template(
        "attack_surface.html",
        completed=len(completed_ids),
        assets_with_ports=sum(1 for a in assets if a.ports),
        services=len(exposure),
        total_findings=len(findings),
        sev_counts=severity_counts(findings),
        exposure=exposure,
        latest=latest,
        surface=surface,
    )


@bp.get("/scans")
def scan_list():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("scans.html", scans=scans,
                           open_counts=_open_finding_counts(
                               [s.id for s in scans]))


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
    closed = sum(1 for f in findings if f.status in CLOSED_STATUSES)
    remediation = {"total": len(findings), "closed": closed,
                   "open": len(findings) - closed}
    return render_template("scan_detail.html", scan=scan, findings=findings,
                           sev_counts=sev_counts, formula_text=FORMULA_TEXT,
                           remediation=remediation,
                           finding_statuses=FINDING_STATUSES)


@bp.post("/findings/<int:finding_id>/status")
def finding_status(finding_id):
    """Triage one finding: mark it acknowledged / resolved / false positive.

    This is a human judgment about a measured result — it never changes
    what the scanner observed, only how the finding is tracked.
    """
    finding = Finding.query.get_or_404(finding_id)
    fallback = url_for("main.scan_detail", scan_id=finding.scan_id)
    new_status = request.form.get("status", "")
    if new_status not in FINDING_STATUSES:
        flash("Unknown status — nothing changed.", "error")
        return _safe_back(fallback)
    finding.status = new_status
    finding.status_note = request.form.get("note", "").strip() or None
    finding.status_updated_at = datetime.now(timezone.utc)
    db.session.commit()
    flash(f"Finding marked as {new_status.replace('_', ' ')}.", "info")
    return _safe_back(fallback)


@bp.get("/scans/<int:scan_id>/report")
def scan_report(scan_id):
    """Printable assessment report, generated on demand from live data.

    Use the browser's Print → Save as PDF for a PDF copy. The report says
    when it was generated and never claims more than the data supports.
    """
    scan = Scan.query.get_or_404(scan_id)
    findings = (Finding.query.filter_by(scan_id=scan_id).all())
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id))
    open_ports = [p for a in scan.assets for p in a.ports]
    open_ports.sort(key=lambda p: (p.asset.ip_address, p.port))
    return render_template(
        "report.html", scan=scan, findings=findings,
        sev_counts=severity_counts(findings), formula_text=FORMULA_TEXT,
        assets=sorted(scan.assets, key=lambda a: a.ip_address),
        open_ports=open_ports,
        closed=sum(1 for f in findings if f.status in CLOSED_STATUSES),
        generated_at=datetime.now(timezone.utc),
    )


@bp.get("/scans/compare")
def scan_compare():
    """Side-by-side diff of two completed scans: new/gone findings,
    opened/closed ports, risk delta."""
    completed = (Scan.query.filter_by(status="completed")
                 .order_by(Scan.completed_at.desc()).all())
    a_id = request.args.get("a", type=int)
    b_id = request.args.get("b", type=int)
    result = None
    if a_id and b_id and a_id != b_id:
        a = next((s for s in completed if s.id == a_id), None)
        b = next((s for s in completed if s.id == b_id), None)
        if a and b:
            f_before = Finding.query.filter_by(scan_id=a.id).all()
            f_after = Finding.query.filter_by(scan_id=b.id).all()
            p_before = Port.query.filter_by(scan_id=a.id).all()
            p_after = Port.query.filter_by(scan_id=b.id).all()
            f_diff = compare_findings(f_before, f_after)
            p_diff = compare_ports(p_before, p_after)

            def _fkey(pair):
                f = pair[1] or pair[0]
                ip = f.asset.ip_address if f.asset else ""
                return (SEVERITY_RANK.get(f.severity, 99),
                        f.rule_id or "", ip)

            def _pkey(pair):
                p = pair[1] or pair[0]
                ip = p.asset.ip_address if p.asset else ""
                return (ip, p.port)

            for key in ("new", "gone", "same"):
                f_diff[key].sort(key=_fkey)
            for key in ("opened", "closed", "same"):
                p_diff[key].sort(key=_pkey)
            result = {
                "summary": summarize(a, b, f_diff, p_diff),
                "findings": f_diff, "ports": p_diff,
            }
    return render_template("compare.html", completed=completed,
                           a_id=a_id, b_id=b_id, result=result)
