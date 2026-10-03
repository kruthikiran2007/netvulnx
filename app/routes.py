"""Web pages and actions.

A "blueprint" is Flask's way of grouping related pages together.
Each function below handles one URL (the @bp.get / @bp.post line above it
says which URL and which HTTP method).

Milestone-2 note: scans now run on BACKGROUND threads (scanner/jobs.py),
so the authorize POST returns immediately and the detail page polls
GET /api/scans/<id>/status for live progress.
"""
import math
import json
import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, current_app, jsonify, abort, session)

from sqlalchemy import func

from app import db
from app import auth as auth_lib
from app import mail as mail_lib
from app.models import (Scan, Asset, Port, Finding, FINDING_STATUSES,
                        CLOSED_STATUSES, User, AuditEvent, ScheduledScan,
                        ApiToken, PasswordResetToken, Baseline)
from app.drift import drift_for_scan
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


def _safe_webhook_url(raw):
    """Accept only http/https webhook URLs; anything else is stored as None
    rather than letting file://, gopher:// etc. into the database."""
    url = (raw or "").strip()
    if not url:
        return None
    if url.lower().startswith(("http://", "https://")):
        return url
    return None


def _require_role(minimum):
    """Route decorator (Milestone 15): reject below a role rank.

    Viewers read; operators act on scans; admins manage everything.
    """
    import functools

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not auth_lib.has_role(auth_lib.current_user(), minimum):
                abort(403, description=f"Requires the '{minimum}' role.")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


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


@bp.get("/topology")
def topology_view():
    """Network topology (Milestone 21): observed hosts grouped into /24
    zones, drawn as server-side SVG. See app/topology.py for exactly what
    the picture does and does not claim."""
    from app import topology as topo_lib
    assets = (Asset.query.join(Scan)
              .filter(Scan.status == "completed")
              .order_by(Asset.checked_at.desc()).all())
    # One node per host: keep the most recent observation of each IP.
    seen = {}
    for a in assets:
        seen.setdefault(a.ip_address, a)
    nodes = []
    for a in seen.values():
        live = [f for f in a.findings
                if f.status not in CLOSED_STATUSES]
        worst = worst_severity(f.severity for f in live)
        services = sorted({p.service for p in a.ports
                           if p.service and p.service != "unknown"})
        nodes.append((a, worst, len(a.ports), services))
    zones, edges = topo_lib.build_topology(nodes)
    return render_template("topology.html",
                           svg=topo_lib.render_svg(zones, edges),
                           zone_count=len(zones), host_count=len(nodes))


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
@_require_role("operator")
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
@_require_role("operator")
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
    auth_lib.log_audit("scan.created",
                       f"scan #{scan.id} '{scan.name}' -> {scan.target_raw} "
                       f"[{scan.profile}]")
    # Step 2 (next page): the authorization gate.
    return redirect(url_for("main.authorize_scan", scan_id=scan.id))


@bp.get("/scans/<int:scan_id>/authorize")
@_require_role("operator")
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
@_require_role("operator")
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
        auth_lib.log_audit("scan.cancelled",
                           f"scan #{scan.id} '{scan.name}' declined at gate")
        flash("Scan cancelled — nothing was sent to the target.", "info")
        return redirect(url_for("main.scan_list"))

    scan.authorized = True
    scan.authorized_at = datetime.now(timezone.utc)
    scan.status = "running"
    scan.started_at = scan.authorized_at
    scan.current_stage = "Starting…"
    db.session.commit()
    # Authenticated checks (Milestone 21): optional credentials from the
    # form go ONLY into the in-memory vault — never the database, never
    # the audit log. The engine pops them once when the scan starts.
    from scanner import authchecks
    auth_enabled = authchecks.store_credentials(
        scan.id,
        request.form.get("auth_username", ""),
        request.form.get("auth_password", ""))
    auth_lib.log_audit("scan.authorized",
                       f"scan #{scan.id} '{scan.name}' -> {scan.target_raw}" +
                       (" [authenticated checks enabled]"
                        if auth_enabled else ""))

    jobs.start_scan_job(current_app._get_current_object(), scan.id)
    flash("Scan started in the background — progress is live below.", "info")
    return redirect(url_for("main.scan_detail", scan_id=scan.id))


@bp.post("/scans/<int:scan_id>/cancel")
@_require_role("operator")
def cancel_scan(scan_id):
    """Ask a running scan to stop. The worker checks between phases/chunks."""
    scan = Scan.query.get_or_404(scan_id)
    if scan.status == "running" and jobs.cancel_scan_job(scan.id):
        auth_lib.log_audit("scan.cancelled",
                           f"scan #{scan.id} '{scan.name}' stop requested")
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
    # Milestone 10: for scheduled runs, what changed since the last run.
    drift = drift_for_scan(scan) if scan.schedule_id else None
    return render_template("scan_detail.html", scan=scan, findings=findings,
                           sev_counts=sev_counts, formula_text=FORMULA_TEXT,
                           remediation=remediation,
                           finding_statuses=FINDING_STATUSES,
                           drift=drift)


@bp.post("/findings/<int:finding_id>/status")
@_require_role("operator")
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
    auth_lib.log_audit("finding.triaged",
                       f"finding #{finding.id} '{finding.title}' -> {new_status}")
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


@bp.post("/scans/<int:scan_id>/baseline")
@_require_role("operator")
def set_baseline(scan_id):
    """Pin a completed scan as the drift baseline for its target.

    One baseline per target: setting a new one replaces the old. The
    drift view then compares this baseline against the newest completed
    scan of the same target.
    """
    scan = Scan.query.get_or_404(scan_id)
    if scan.status != "completed":
        flash("Only completed scans can be baselines.", "error")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))
    existing = Baseline.query.filter_by(target=scan.target_raw).first()
    if existing:
        existing.scan_id = scan.id
        existing.note = request.form.get("note", "").strip() or None
        existing.created_at = datetime.now(timezone.utc)
        action = "updated"
    else:
        existing = Baseline(target=scan.target_raw, scan_id=scan.id,
                            note=request.form.get("note", "").strip() or None)
        db.session.add(existing)
        action = "set"
    db.session.commit()
    auth_lib.log_audit("baseline.set",
                       f"baseline for '{scan.target_raw}' {action} -> "
                       f"scan #{scan.id}")
    flash(f"Baseline {action} for {scan.target_raw}.", "info")
    return redirect(url_for("main.baseline_list"))


@bp.get("/baselines")
def baseline_list():
    """All pinned baselines, newest first."""
    baselines = Baseline.query.order_by(Baseline.created_at.desc()).all()
    return render_template("baselines.html", baselines=baselines)


@bp.get("/baselines/<int:baseline_id>")
def baseline_detail(baseline_id):
    """Drift view: baseline vs the newest completed scan of the same target."""
    baseline = Baseline.query.get_or_404(baseline_id)
    base_scan = baseline.scan
    latest = (Scan.query
              .filter(Scan.target_raw == baseline.target,
                      Scan.status == "completed",
                      Scan.id != base_scan.id)
              .order_by(Scan.completed_at.desc()).first())
    result = None
    if latest:
        f_before = Finding.query.filter_by(scan_id=base_scan.id).all()
        f_after = Finding.query.filter_by(scan_id=latest.id).all()
        p_before = Port.query.filter_by(scan_id=base_scan.id).all()
        p_after = Port.query.filter_by(scan_id=latest.id).all()
        f_diff = compare_findings(f_before, f_after)
        p_diff = compare_ports(p_before, p_after)

        def _fkey(pair):
            f = pair[1] or pair[0]
            ip = f.asset.ip_address if f.asset else ""
            return (SEVERITY_RANK.get(f.severity, 99), f.rule_id or "", ip)

        def _pkey(pair):
            p = pair[1] or pair[0]
            ip = p.asset.ip_address if p.asset else ""
            return (ip, p.port)

        for key in ("new", "gone", "same"):
            f_diff[key].sort(key=_fkey)
        for key in ("opened", "closed", "same"):
            p_diff[key].sort(key=_pkey)
        result = {"summary": summarize(base_scan, latest, f_diff, p_diff),
                  "findings": f_diff, "ports": p_diff}
    return render_template("baseline_detail.html", baseline=baseline,
                           base_scan=base_scan, latest=latest, result=result)


# ---------------------------------------------------------------------------
# Authentication (Milestone 8). The login gate itself lives in
# app/__init__.py (_require_login); these are the pages it lets through.
# ---------------------------------------------------------------------------

@bp.get("/setup")
def setup():
    """First-run page: create the initial admin account.

    Only reachable while no users exist at all — afterwards it redirects
    to the login page, so nobody can re-run setup to hijack the app.
    """
    if User.query.count() > 0:
        return redirect(url_for("main.login"))
    return render_template("setup.html")


@bp.post("/setup")
def setup_submit():
    if User.query.count() > 0:
        abort(403, description="Setup already completed.")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not auth_lib.valid_username(username):
        flash("Username: 3-40 characters, letters/digits/_/-.", "error")
        return render_template("setup.html"), 400
    if not auth_lib.valid_password(password):
        flash("Password must be at least 8 characters.", "error")
        return render_template("setup.html"), 400
    user = User(username=username,
                password_hash=auth_lib.hash_password(password),
                role="admin")
    db.session.add(user)
    db.session.commit()
    auth_lib.login_user(user)
    auth_lib.log_audit("user.created",
                       f"initial admin account '{username}'", actor=username)
    flash(f"Welcome, {username} — admin account created.", "info")
    return redirect(url_for("main.dashboard"))


@bp.get("/login")
def login():
    if auth_lib.current_user():
        return redirect(url_for("main.dashboard"))
    return render_template("login.html", next=request.args.get("next", ""))


@bp.post("/login")
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = request.remote_addr

    # Brute-force protection (Milestone 13): too many failures from this
    # username+IP locks the combination out for 15 minutes.
    locked, remaining = auth_lib.throttle_status(username, ip)
    if locked:
        mins = max(1, int(remaining.total_seconds() // 60))
        auth_lib.log_audit("login.locked", f"username '{username}'",
                           actor=username or "anonymous")
        flash(f"Too many failed attempts — try again in about {mins} "
              f"minute(s).", "error")
        return render_template("login.html",
                               next=request.form.get("next", "")), 429

    user = User.query.filter_by(username=username).first()
    if not auth_lib.verify_password(user, password):
        # Same message either way: don't reveal whether the username exists.
        just_locked = auth_lib.record_failed_login(username, ip)
        auth_lib.log_audit("login.failed", f"username '{username}'",
                           actor=username or "anonymous")
        if just_locked:
            flash("Too many failed attempts — this login is locked for "
                  "15 minutes.", "error")
        else:
            flash("Wrong username or password.", "error")
        return render_template("login.html",
                               next=request.form.get("next", "")), 401

    auth_lib.clear_throttle(username, ip)
    # Session fixation defense: drop any pre-login session data before
    # marking this session as the user's.
    session.clear()
    auth_lib.login_user(user)
    auth_lib.log_audit("login.ok", "", actor=user.username)
    flash(f"Welcome back, {user.username}.", "info")
    nxt = request.form.get("next", "")
    # Browsers treat backslashes as slashes, so "/\evil.com" would escape
    # to an external site despite passing the startswith checks. Check the
    # raw and percent-decoded forms (%5c is an encoded backslash).
    decoded = unquote(nxt)
    if (nxt.startswith("/") and not nxt.startswith("//")
            and "\\" not in nxt and "\\" not in decoded):
        return redirect(nxt)
    return redirect(url_for("main.dashboard"))


@bp.post("/logout")
def logout():
    user = auth_lib.current_user()
    auth_lib.logout_user()
    if user:
        auth_lib.log_audit("logout", "", actor=user.username)
    flash("Logged out.", "info")
    return redirect(url_for("main.login"))


@bp.get("/lang/<code>")
def set_language(code):
    """Switch the UI language (Milestone 21). Stored in the session;
    unknown codes are ignored and fall back to English."""
    from app import i18n as i18n_lib
    i18n_lib.set_lang(code)
    return _safe_back(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# Password reset by email (Milestone 20)
# ---------------------------------------------------------------------------

def _utcnow():
    return datetime.now(timezone.utc)


def _find_reset_token(raw):
    """Return the live PasswordResetToken for a raw token string, or None."""
    if not raw or len(raw) > 128:
        return None
    rec = PasswordResetToken.query.filter_by(
        token_hash=auth_lib.hash_token(raw)).first()
    if rec is None or not rec.is_valid:
        return None
    return rec


@bp.get("/forgot-password")
def forgot_form():
    """Ask for a username; email a reset link if the account can receive one."""
    if auth_lib.current_user():
        return redirect(url_for("main.dashboard"))
    return render_template("forgot.html",
                           smtp_enabled=current_app.config.get("SMTP_ENABLED"))


@bp.post("/forgot-password")
def forgot_submit():
    if auth_lib.current_user():
        return redirect(url_for("main.dashboard"))
    username = request.form.get("username", "").strip()
    # The reply is ALWAYS the same: we never reveal whether the username
    # exists, has an email, or was rate-limited (no user enumeration).
    reply = ("If an account with that username exists and has an email "
             "address on file, a password-reset link is on its way. The "
             "link expires in one hour.")
    user = User.query.filter_by(username=username).first()
    if user and user.email and current_app.config.get("SMTP_ENABLED"):
        hour_ago = _utcnow() - timedelta(hours=1)
        recent = PasswordResetToken.query.filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_at > hour_ago).count()
        if recent < current_app.config.get("RESET_MAX_PER_HOUR", 5):
            raw = secrets.token_urlsafe(32)
            rec = PasswordResetToken(
                user_id=user.id,
                token_hash=auth_lib.hash_token(raw),
                expires_at=_utcnow() + timedelta(
                    seconds=current_app.config.get("RESET_TOKEN_TTL_SECONDS", 3600)))
            db.session.add(rec)
            db.session.commit()
            reset_url = url_for("main.reset_form", token=raw, _external=True)
            ok, err = mail_lib.send_password_reset(
                user.email, user.username, reset_url)
            if not ok:
                # The email failed; burn the token so a dead link can't
                # linger, and keep the generic reply (the log has details).
                rec.used_at = _utcnow()
                db.session.commit()
                current_app.logger.warning(
                    "password reset email failed for '%s': %s",
                    username, err)
            auth_lib.log_audit("password.reset_requested",
                               f"username '{username}'", actor=username)
    flash(reply, "info")
    return render_template("forgot.html", smtp_enabled=current_app.config.get("SMTP_ENABLED"))


@bp.get("/reset-password/<token>")
def reset_form(token):
    if auth_lib.current_user():
        return redirect(url_for("main.dashboard"))
    if _find_reset_token(token) is None:
        flash("That reset link is invalid or has expired — request a new "
              "one.", "error")
        return redirect(url_for("main.forgot_form"))
    return render_template("reset.html", token=token)


@bp.post("/reset-password/<token>")
def reset_submit(token):
    if auth_lib.current_user():
        return redirect(url_for("main.dashboard"))
    rec = _find_reset_token(token)
    if rec is None:
        flash("That reset link is invalid or has expired — request a new "
              "one.", "error")
        return render_template("forgot.html",
                               smtp_enabled=current_app.config.get("SMTP_ENABLED")), 401
    new = request.form.get("new_password", "")
    if not auth_lib.valid_password(new):
        flash("The new password must be at least 8 characters.", "error")
        return render_template("reset.html", token=token), 400
    user = rec.user
    if auth_lib.verify_password(user, new):
        flash("The new password can't be the same as the current one.",
              "error")
        return render_template("reset.html", token=token), 400
    user.password_hash = auth_lib.hash_password(new)
    # Single-use: burn this token and every other outstanding token for the
    # same account, so old links die with the password change.
    now = _utcnow()
    rec.used_at = now
    for other in PasswordResetToken.query.filter_by(
            user_id=user.id, used_at=None).all():
        other.used_at = now
    db.session.commit()
    auth_lib.log_audit("password.reset_completed", "",
                       actor=user.username)
    flash("Password reset — log in with your new password.", "info")
    return redirect(url_for("main.login"))


@bp.get("/account/password")
def password_form():
    """Change your own password (Milestone 13)."""
    user = auth_lib.current_user()
    if not user:
        return redirect(url_for("main.login"))
    return render_template("password.html", current_email=user.email)


@bp.post("/account/email")
def email_submit():
    """Set your own reset-email address (Milestone 20)."""
    user = auth_lib.current_user()
    if not user:
        return redirect(url_for("main.login"))
    email = request.form.get("email", "").strip() or None
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        flash("That email address doesn't look valid.", "error")
        return render_template("password.html",
                               current_email=user.email), 400
    user.email = email
    db.session.commit()
    auth_lib.log_audit("account.email_updated", "", actor=user.username)
    flash("Email address saved.", "info")
    return redirect(url_for("main.password_form"))


@bp.post("/account/password")
def password_submit():
    user = auth_lib.current_user()
    if not user:
        return redirect(url_for("main.login"))
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    if not auth_lib.verify_password(user, current):
        flash("Your current password is wrong — nothing changed.", "error")
        return render_template("password.html"), 401
    if not auth_lib.valid_password(new):
        flash("The new password must be at least 8 characters.", "error")
        return render_template("password.html"), 400
    if auth_lib.verify_password(user, new):
        flash("The new password can't be the same as the current one.",
              "error")
        return render_template("password.html"), 400
    user.password_hash = auth_lib.hash_password(new)
    db.session.commit()
    auth_lib.log_audit("password.changed", "", actor=user.username)
    flash("Password changed.", "info")
    return redirect(url_for("main.dashboard"))


@bp.get("/audit")
def audit_log():
    """Recent audit events. Admins only — it's the tamper-evident trail."""
    user = auth_lib.current_user()
    if not user or not user.is_admin:
        abort(403, description="Admins only.")
    events = (AuditEvent.query
              .order_by(AuditEvent.created_at.desc()).limit(200).all())
    return render_template("audit.html", events=events)


# ---------------- Milestone 10: recurring scans ----------------

@bp.get("/schedules")
def schedule_list():
    """All recurring scan schedules, soonest run first."""
    schedules = (ScheduledScan.query
                 .order_by(ScheduledScan.next_run_at).all())
    return render_template("schedules.html", schedules=schedules)


@bp.get("/schedules/new")
@_require_role("operator")
def schedule_new_form():
    return render_template("new_schedule.html",
                           default_ports=Config.DEFAULT_PORTS,
                           profiles=Config.SCAN_PROFILES,
                           intervals=ScheduledScan.INTERVALS)


@bp.post("/schedules/new")
@_require_role("operator")
def schedule_new_submit():
    """Create a recurring scan.

    The authorization checkbox is the recurring-scan version of the
    one-off safety gate: ticking it is the explicit opt-in that lets
    the scheduler touch this target on its own, and it's audit-logged.
    """
    from datetime import timedelta
    user = auth_lib.current_user()
    name = request.form.get("name", "").strip() or "Untitled schedule"
    target_text = request.form.get("target", "")
    ports_text = request.form.get("ports", "")
    profile = request.form.get("profile", "standard")
    interval = request.form.get("interval", "daily")
    if profile not in Config.SCAN_PROFILES:
        profile = "standard"
    if interval not in ScheduledScan.INTERVALS:
        interval = "daily"

    if request.form.get("authorize_recurring") != "yes":
        flash("Tick the authorization checkbox — recurring scans need your "
              "explicit opt-in before anything is scheduled.", "error")
        return render_template("new_schedule.html",
                               default_ports=Config.DEFAULT_PORTS,
                               profiles=Config.SCAN_PROFILES,
                               intervals=ScheduledScan.INTERVALS,
                               target=target_text, ports=ports_text,
                               name=name, profile=profile,
                               interval=interval), 400
    try:
        target = parse_target(target_text, allow_public=Config.ALLOW_PUBLIC_TARGETS)
        ports = _resolve_ports(profile, ports_text)
    except TargetError as exc:
        flash(str(exc), "error")
        return render_template("new_schedule.html",
                               default_ports=Config.DEFAULT_PORTS,
                               profiles=Config.SCAN_PROFILES,
                               intervals=ScheduledScan.INTERVALS,
                               target=target_text, ports=ports_text,
                               name=name, profile=profile,
                               interval=interval), 400

    sched = ScheduledScan(
        name=name,
        target_raw=target_text,
        target_type=target["type"],
        ports_raw=",".join(map(str, ports)),
        profile=profile,
        interval=interval,
        # First run within a few minutes so the user can see it working,
        # then every interval after that.
        next_run_at=datetime.now(timezone.utc) + timedelta(minutes=2),
        created_by=user.username if user else "admin",
        webhook_url=_safe_webhook_url(request.form.get("webhook_url", "")),
    )
    db.session.add(sched)
    db.session.commit()
    auth_lib.log_audit(
        "schedule.created",
        f"schedule #{sched.id} '{sched.name}' -> {sched.target_raw} "
        f"[{sched.profile}, {sched.interval}] — recurring authorization "
        f"granted by {sched.created_by}")
    flash(f"Schedule '{sched.name}' created — first run within a few "
          f"minutes, then {interval}.", "info")
    return redirect(url_for("main.schedule_list"))


@bp.post("/schedules/<int:schedule_id>/toggle")
@_require_role("operator")
def schedule_toggle(schedule_id):
    """Enable/disable a schedule. Disabled schedules never run."""
    sched = ScheduledScan.query.get_or_404(schedule_id)
    sched.enabled = not sched.enabled
    db.session.commit()
    state = "enabled" if sched.enabled else "disabled"
    auth_lib.log_audit("schedule.toggled",
                       f"schedule #{sched.id} '{sched.name}' {state}")
    flash(f"Schedule '{sched.name}' {state}.", "info")
    return redirect(url_for("main.schedule_list"))


@bp.post("/schedules/<int:schedule_id>/delete")
@_require_role("operator")
def schedule_delete(schedule_id):
    """Delete a schedule and its runs. Findings history goes with them."""
    sched = ScheduledScan.query.get_or_404(schedule_id)
    name = sched.name
    db.session.delete(sched)
    db.session.commit()
    auth_lib.log_audit("schedule.deleted", f"schedule #{schedule_id} '{name}'")
    flash(f"Schedule '{name}' deleted.", "info")
    return redirect(url_for("main.schedule_list"))


# ---------------- Milestone 11: exports ----------------

def _export_filename(scan, ext):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan.name)
    return f"netvulnx-scan-{scan.id}-{safe[:40]}.{ext}"


@bp.get("/scans/<int:scan_id>/export.csv")
def export_csv(scan_id):
    """Download all findings as CSV (for spreadsheets / ticketing tools)."""
    from app.exports import findings_csv
    scan = Scan.query.get_or_404(scan_id)
    csv_text = findings_csv(scan)
    return current_app.response_class(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename={_export_filename(scan, 'csv')}"})


@bp.get("/scans/<int:scan_id>/export.json")
def export_json(scan_id):
    """Download the full scan (metadata, assets, findings) as JSON."""
    from app.exports import scan_json
    scan = Scan.query.get_or_404(scan_id)
    body = json.dumps(scan_json(scan), indent=2)
    return current_app.response_class(
        body,
        mimetype="application/json",
        headers={"Content-Disposition":
                 f"attachment; filename={_export_filename(scan, 'json')}"})


# ---------------- Milestone 14: API tokens ----------------

def _require_admin():
    user = auth_lib.current_user()
    if not user or not user.is_admin:
        abort(403, description="Admins only.")


@bp.get("/settings/tokens")
def token_list():
    """API tokens for automation. Admins only."""
    _require_admin()
    tokens = ApiToken.query.order_by(ApiToken.created_at.desc()).all()
    return render_template("tokens.html", tokens=tokens,
                           new_secret=request.args.get("new_secret"),
                           new_name=request.args.get("new_name"))


@bp.post("/settings/tokens/new")
def token_create():
    """Create a token. The secret is shown ONCE — never stored in plain."""
    import secrets as _secrets
    _require_admin()
    user = auth_lib.current_user()
    name = request.form.get("name", "").strip() or "Untitled token"
    secret = auth_lib.TOKEN_PREFIX + _secrets.token_hex(16)
    token = ApiToken(name=name[:120],
                     prefix=secret[:len(auth_lib.TOKEN_PREFIX) + 8],
                     token_hash=auth_lib.hash_token(secret),
                     user_id=user.id)
    db.session.add(token)
    db.session.commit()
    auth_lib.log_audit("token.created",
                       f"token '{name}' (…{token.prefix[-4:]}) for "
                       f"{user.username}")
    flash("Token created — copy it now. It will never be shown again.",
          "info")
    return redirect(url_for("main.token_list", new_secret=secret,
                            new_name=name))


@bp.post("/settings/tokens/<int:token_id>/revoke")
def token_revoke(token_id):
    _require_admin()
    token = ApiToken.query.get_or_404(token_id)
    token.revoked = True
    db.session.commit()
    auth_lib.log_audit("token.revoked", f"token '{token.name}'")
    flash(f"Token '{token.name}' revoked.", "info")
    return redirect(url_for("main.token_list"))


# ---------------- Milestone 15: team roles & user management ----------------

@bp.get("/users")
@_require_role("admin")
def user_list():
    users = User.query.order_by(User.created_at).all()
    return render_template("users.html", users=users, roles=User.ROLES)


@bp.post("/users/new")
@_require_role("admin")
def user_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "operator")
    email = request.form.get("email", "").strip() or None
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        flash("That email address doesn't look valid.", "error")
        return redirect(url_for("main.user_list"))
    if not auth_lib.valid_username(username):
        flash("Username: 3-40 characters, letters/digits/_/-.", "error")
        return redirect(url_for("main.user_list"))
    if not auth_lib.valid_password(password):
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("main.user_list"))
    if role not in User.ROLES:
        role = "operator"
    if User.query.filter_by(username=username).first():
        flash("That username is taken.", "error")
        return redirect(url_for("main.user_list"))
    user = User(username=username,
                password_hash=auth_lib.hash_password(password), role=role,
                email=email)
    db.session.add(user)
    db.session.commit()
    auth_lib.log_audit("user.created",
                       f"account '{username}' with role '{role}'")
    flash(f"User '{username}' created as {role}.", "info")
    return redirect(url_for("main.user_list"))


@bp.post("/users/<int:user_id>/role")
@_require_role("admin")
def user_set_role(user_id):
    user = User.query.get_or_404(user_id)
    me = auth_lib.current_user()
    role = request.form.get("role", "")
    if role not in User.ROLES:
        flash("Unknown role.", "error")
        return redirect(url_for("main.user_list"))
    if user.id == me.id and role != "admin":
        flash("You can't demote yourself.", "error")
        return redirect(url_for("main.user_list"))
    if user.role == "admin" and role != "admin" and \
            User.query.filter_by(role="admin").count() <= 1:
        flash("You can't demote the last admin.", "error")
        return redirect(url_for("main.user_list"))
    user.role = role
    db.session.commit()
    auth_lib.log_audit("user.role_changed",
                       f"account '{user.username}' -> role '{role}'")
    flash(f"'{user.username}' is now {role}.", "info")
    return redirect(url_for("main.user_list"))


@bp.post("/users/<int:user_id>/delete")
@_require_role("admin")
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    me = auth_lib.current_user()
    if user.id == me.id:
        flash("You can't delete yourself.", "error")
        return redirect(url_for("main.user_list"))
    if user.role == "admin" and \
            User.query.filter_by(role="admin").count() <= 1:
        flash("You can't delete the last admin.", "error")
        return redirect(url_for("main.user_list"))
    # Revoke their API tokens too — a deleted user keeps no access.
    ApiToken.query.filter_by(user_id=user.id).update({"revoked": True})
    db.session.delete(user)
    db.session.commit()
    auth_lib.log_audit("user.deleted", f"account '{user.username}'")
    flash(f"User '{user.username}' deleted.", "info")
    return redirect(url_for("main.user_list"))
