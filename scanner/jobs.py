"""Background scan jobs.

Why background? A deep scan of a /24 can take minutes. The web request that
starts the scan must return immediately; the scan runs on a worker thread
while the browser polls for progress.

Design notes for the curious:
  - One daemon thread per scan. Daemon = it won't block app shutdown.
  - Cancellation via threading.Event, checked regularly by the engine.
  - Flask-SQLAlchemy needs an "app context" in each thread before touching
    the database — the engine pushes one for its whole run.
  - Crash recovery: if the app restarts mid-scan, any scan still marked
    "running" is stale. recover_interrupted() marks them honestly instead
    of leaving them stuck forever.
"""
import threading

_jobs = {}  # scan_id -> {"thread": Thread, "cancel": Event}
_lock = threading.Lock()


def start_scan_job(app, scan_id: int):
    """Launch the scan engine on a background thread. Never blocks."""
    from scanner import engine  # lazy import: engine imports this module too
    cancel = threading.Event()
    thread = threading.Thread(target=engine.run_scan,
                              args=(app, scan_id, cancel),
                              name=f"netvulnx-scan-{scan_id}",
                              daemon=True)
    with _lock:
        _jobs[scan_id] = {"thread": thread, "cancel": cancel}
    thread.start()


def cancel_scan_job(scan_id: int) -> bool:
    """Ask a running scan to stop. Returns False if no such job is running."""
    with _lock:
        job = _jobs.get(scan_id)
    if job is None:
        return False
    job["cancel"].set()
    return True


def _finish_job(scan_id: int):
    with _lock:
        _jobs.pop(scan_id, None)


def recover_interrupted(app):
    """Mark scans left 'running' by a previous process as interrupted.

    Called once at app startup. Without this, a restart mid-scan would leave
    rows claiming to be "running" forever — a lie in the database.
    """
    with app.app_context():
        from app import db
        from app.models import Scan
        stale = Scan.query.filter_by(status="running").all()
        for scan in stale:
            scan.status = "interrupted"
            scan.current_stage = "Interrupted"
            scan.error = ("Scan was interrupted (the application stopped "
                          "while it was running). Results so far are kept.")
        if stale:
            db.session.commit()
