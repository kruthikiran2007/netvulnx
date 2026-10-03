# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for recurring scans and drift detection (Milestone 10).

Throwaway SQLite databases; the background scheduler is never started
(start_scan_job is stubbed so no real scanning happens).
"""
import re
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from app import create_app, db
from app.models import ScheduledScan, Scan, Finding, AuditEvent
from app.drift import compare_scans, drift_for_scan
from scanner import scheduler as scheduler_lib
from config import Config


@pytest.fixture()
def app_and_client():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    app = create_app(_TestConfig)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield app, c


def _token(client, url):
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="_csrf_token" value="([^"]+)"', html)
    assert m, f"no CSRF token on {url}"
    return m.group(1)


def _setup_admin(client, username="admin", password="testpass123"):
    tok = _token(client, "/setup")
    r = client.post("/setup", data={"_csrf_token": tok, "username": username,
                                    "password": password})
    assert r.status_code == 302


def _new_schedule(client, **over):
    data = {"_csrf_token": _token(client, "/schedules/new"),
            "name": "nightly", "target": "127.0.0.1",
            "profile": "quick", "ports": "", "interval": "daily",
            "authorize_recurring": "yes"}
    data.update(over)
    return client.post("/schedules/new", data=data)


# --- creation ---------------------------------------------------------------

def test_schedule_requires_authorization_checkbox(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    r = _new_schedule(client, authorize_recurring="nope")
    assert r.status_code == 400
    with app.app_context():
        assert ScheduledScan.query.count() == 0


def test_schedule_created_with_valid_target(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    r = _new_schedule(client)
    assert r.status_code == 302
    with app.app_context():
        s = ScheduledScan.query.one()
        assert s.name == "nightly"
        assert s.target_raw == "127.0.0.1"
        assert s.enabled is True
        assert s.created_by == "admin"
        # First run scheduled soon (not a full interval out).
        nxt = s.next_run_at.replace(tzinfo=timezone.utc)
        delta = nxt - datetime.now(timezone.utc)
        assert timedelta(0) < delta < timedelta(minutes=10)
        # Audit trail records the standing authorization.
        ev = AuditEvent.query.filter_by(action="schedule.created").one()
        assert "recurring authorization" in ev.detail


def test_schedule_rejects_bad_target(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    r = _new_schedule(client, target="8.8.8.8")
    assert r.status_code == 400
    with app.app_context():
        assert ScheduledScan.query.count() == 0


def test_schedule_requires_login(app_and_client):
    _, client = app_and_client
    r = client.get("/schedules")
    assert r.status_code == 302  # login gate redirects


# --- scheduler ----------------------------------------------------------------

def test_advance_moves_one_interval(app_and_client):
    app, _ = app_and_client
    with app.app_context():
        now = datetime.now(timezone.utc)
        s = ScheduledScan(name="x", target_raw="127.0.0.1", target_type="ip",
                          ports_raw="80", profile="quick", interval="weekly",
                          next_run_at=now, created_by="admin")
        s.advance(now)
        assert timedelta(days=6, hours=23) < s.next_run_at - now \
            < timedelta(days=7, hours=1)


def test_run_due_schedules_runs_and_advances(app_and_client, monkeypatch):
    app, client = app_and_client
    _setup_admin(client)
    _new_schedule(client)
    started = []
    monkeypatch.setattr("scanner.jobs.start_scan_job",
                        lambda app_arg, scan_id: started.append(scan_id))
    with app.app_context():
        s = ScheduledScan.query.one()
        # Force it due right now.
        s.next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()
        ran = scheduler_lib.run_due_schedules(app)
        assert ran == 1
        assert started, "scan job was not started"
        scan = Scan.query.get(started[0])
        assert scan.schedule_id == s.id
        assert scan.authorized is True
        assert scan.status == "running"
        # Next run pushed one interval out.
        nxt = s.next_run_at.replace(tzinfo=timezone.utc)
        assert nxt > datetime.now(timezone.utc) + timedelta(hours=23)
        ev = AuditEvent.query.filter_by(action="scan.authorized").one()
        assert "scheduled run" in ev.detail


def test_disabled_schedule_does_not_run(app_and_client, monkeypatch):
    app, client = app_and_client
    _setup_admin(client)
    _new_schedule(client)
    monkeypatch.setattr("scanner.jobs.start_scan_job",
                        lambda app_arg, scan_id: pytest.fail("must not run"))
    with app.app_context():
        s = ScheduledScan.query.one()
        s.enabled = False
        s.next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()
        assert scheduler_lib.run_due_schedules(app) == 0
        assert Scan.query.count() == 0


def test_toggle_and_delete(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    _new_schedule(client)
    with app.app_context():
        sid = ScheduledScan.query.one().id
    tok = _token(client, "/schedules")
    client.post(f"/schedules/{sid}/toggle", data={"_csrf_token": tok})
    with app.app_context():
        assert ScheduledScan.query.get(sid).enabled is False
    tok = _token(client, "/schedules")
    client.post(f"/schedules/{sid}/delete", data={"_csrf_token": tok})
    with app.app_context():
        assert ScheduledScan.query.count() == 0


# --- drift --------------------------------------------------------------------

def _finding(scan_id, rule_id, title):
    return Finding(scan_id=scan_id, asset_id=1, port_id=None,
                   rule_id=rule_id, title=title, severity="high",
                   confidence="likely")


def test_compare_scans_finds_new_and_resolved(app_and_client):
    app, _ = app_and_client
    with app.app_context():
        old = Scan(name="old", target_raw="127.0.0.1", target_type="ip",
                   ports_raw="80", profile="quick", status="completed")
        new = Scan(name="new", target_raw="127.0.0.1", target_type="ip",
                   ports_raw="80", profile="quick", status="completed")
        db.session.add_all([old, new])
        db.session.flush()
        db.session.add_all([
            _finding(old.id, "tls-cert-expired", "expired cert"),
            _finding(old.id, "http-hsts-missing", "no hsts"),
            _finding(new.id, "tls-cert-expired", "expired cert"),
            _finding(new.id, "ftp-anonymous-allowed", "anon ftp"),
        ])
        db.session.commit()
        result = compare_scans(new, old)
        assert [f.rule_id for f in result["new"]] == ["ftp-anonymous-allowed"]
        assert [f.rule_id for f in result["resolved"]] == ["http-hsts-missing"]


def test_drift_for_scan_needs_schedule(app_and_client):
    app, _ = app_and_client
    with app.app_context():
        s = Scan(name="one-off", target_raw="127.0.0.1", target_type="ip",
                 ports_raw="80", profile="quick", status="completed")
        db.session.add(s)
        db.session.commit()
        assert drift_for_scan(s) is None
