"""Recurring scans (Milestone 10).

A BackgroundScheduler ticks every minute and runs any enabled schedule
whose ``next_run_at`` has passed. Each run creates a normal Scan row
(linked via ``schedule_id``) so the whole existing pipeline — progress,
rules, findings, reports — works unchanged.

Safety: a schedule can only be created with the explicit authorization
checkbox ticked ("I authorize recurring scans of this target"), the same
opt-in as the one-off gate, written to the audit log at creation time.
Disabling or deleting a schedule stops future runs immediately.
"""
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

_scheduler = None


def _utcnow():
    return datetime.now(timezone.utc)


def run_scheduled_scan(app, sched):
    """Execute one due schedule: create an authorized Scan and start it."""
    from app import db
    from app.models import Scan
    from app import auth as auth_lib
    from scanner import jobs

    scan = Scan(
        name=f"{sched.name} (scheduled)",
        target_raw=sched.target_raw,
        target_type=sched.target_type,
        ports_raw=sched.ports_raw,
        profile=sched.profile,
        status="running",
        authorized=True,
        authorized_at=_utcnow(),
        started_at=_utcnow(),
        current_stage="Starting…",
        schedule_id=sched.id,
    )
    db.session.add(scan)
    sched.advance(_utcnow())
    db.session.commit()
    auth_lib.log_audit(
        "scan.authorized",
        f"scheduled run: scan #{scan.id} '{sched.name}' -> {sched.target_raw} "
        f"(recurring authorization from schedule #{sched.id})")
    jobs.start_scan_job(app, scan.id)
    return scan


def run_due_schedules(app):
    """Run every enabled schedule whose next_run_at has passed. Returns count."""
    from app import db
    from app.models import ScheduledScan
    now = _utcnow()
    due = (ScheduledScan.query
           .filter(ScheduledScan.enabled.is_(True),
                   ScheduledScan.next_run_at <= now)
           .all())
    ran = 0
    for sched in due:
        try:
            run_scheduled_scan(app, sched)
            ran += 1
        except Exception as exc:
            app.logger.exception("scheduled scan #%s failed: %s",
                                 sched.id, exc)
            db.session.rollback()
    return ran


def _tick(app):
    with app.app_context():
        run_due_schedules(app)


def start_scheduler(app):
    """Start the background scheduler once. Never in tests."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    if app.config.get("TESTING"):
        return None
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(lambda: _tick(app), "interval", seconds=60,
                       id="netvulnx-schedules", replace_existing=True)
    _scheduler.start()
    app.logger.info("scheduler: recurring-scan ticker started (60s)")
    return _scheduler
