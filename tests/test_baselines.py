# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for drift baselines (Milestone 21).

Uses the real Flask app + real database: create scans with findings,
pin a baseline, and check the drift view shows new/gone findings.
"""
import re

import pytest

from app import create_app, db
from app.models import Scan, Asset, Port, Finding, Baseline, User
from config import Config


@pytest.fixture()
def app():
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    class TConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + path
        TESTING = True
        WTF_CSRF_ENABLED = False

    app = create_app(TConfig)
    with app.app_context():
        # one operator user so the login gate is satisfied
        from app import auth as auth_lib
        db.session.add(User(username="op",
                            password_hash=auth_lib.hash_password("password-123"),
                            role="operator"))
        db.session.commit()
        yield app
        # Windows locks open SQLite files: release all pooled connections
        # before deleting, or unlink() raises PermissionError.
        db.session.remove()
        db.engine.dispose()
    os.unlink(path)


@pytest.fixture()
def client(app):
    return app.test_client()


def _login(client):
    m = re.search(r'name="_csrf_token" value="([^"]+)"',
                  client.get("/login").get_data(as_text=True))
    tok = m.group(1)
    r = client.post("/login", data={"_csrf_token": tok, "username": "op",
                                    "password": "password-123"})
    assert r.status_code in (302, 303), r.status_code


def _mk_scan(app, name, target="127.0.0.1", findings=()):
    """Create a completed scan with one asset/port and given findings."""
    with app.app_context():
        scan = Scan(name=name, target_raw=target, target_type="single",
                    ports_raw="80", profile="quick", status="completed")
        db.session.add(scan)
        db.session.flush()
        asset = Asset(scan_id=scan.id, ip_address=target, is_reachable=True)
        db.session.add(asset)
        db.session.flush()
        port = Port(scan_id=scan.id, asset_id=asset.id, port=80,
                    service="http", confidence=90)
        db.session.add(port)
        db.session.flush()
        for rule_id, severity in findings:
            db.session.add(Finding(scan_id=scan.id, asset_id=asset.id,
                                   port_id=port.id, rule_id=rule_id,
                                   title=rule_id, severity=severity,
                                   confidence="confirmed",
                                   description="d", impact="i",
                                   remediation="r"))
        db.session.commit()
        return scan.id


def _csrf(client, url):
    m = re.search(r'name="_csrf_token" value="([^"]+)"',
                  client.get(url).get_data(as_text=True))
    return m.group(1) if m else "x"


def test_set_baseline_and_drift(client, app):
    _login(client)
    old = _mk_scan(app, "week 1", findings=[("rule-a", "high")])
    new = _mk_scan(app, "week 2", findings=[("rule-a", "high"),
                                            ("rule-b", "medium")])
    tok = _csrf(client, f"/scans/{old}")
    r = client.post(f"/scans/{old}/baseline",
                    data={"_csrf_token": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert b"Baseline set" in r.data

    with app.app_context():
        bl = Baseline.query.filter_by(target="127.0.0.1").one()
        assert bl.scan_id == old

    # Drift view: rule-b is new, nothing gone.
    r = client.get(f"/baselines/{bl.id}")
    assert r.status_code == 200
    assert b"rule-b" in r.data
    assert b"Findings: new (1)" in r.data
    assert b"Findings: gone (0)" in r.data


def test_baseline_replaced_not_duplicated(client, app):
    _login(client)
    s1 = _mk_scan(app, "s1")
    s2 = _mk_scan(app, "s2")
    tok = _csrf(client, f"/scans/{s1}")
    client.post(f"/scans/{s1}/baseline", data={"_csrf_token": tok})
    tok = _csrf(client, f"/scans/{s2}")
    client.post(f"/scans/{s2}/baseline", data={"_csrf_token": tok})
    with app.app_context():
        assert Baseline.query.filter_by(target="127.0.0.1").count() == 1
        assert Baseline.query.filter_by(target="127.0.0.1").one().scan_id == s2


def test_baseline_requires_completed(client, app):
    _login(client)
    with app.app_context():
        scan = Scan(name="running", target_raw="127.0.0.1",
                    target_type="single", ports_raw="80", profile="quick",
                    status="running")
        db.session.add(scan)
        db.session.commit()
        sid = scan.id
    tok = _csrf(client, f"/scans/{sid}")
    r = client.post(f"/scans/{sid}/baseline", data={"_csrf_token": tok},
                    follow_redirects=True)
    assert b"Only completed scans" in r.data
    with app.app_context():
        assert Baseline.query.count() == 0


def test_drift_no_newer_scan(client, app):
    _login(client)
    s1 = _mk_scan(app, "only")
    tok = _csrf(client, f"/scans/{s1}")
    client.post(f"/scans/{s1}/baseline", data={"_csrf_token": tok})
    with app.app_context():
        bl = Baseline.query.one()
    r = client.get(f"/baselines/{bl.id}")
    assert b"No newer completed scan" in r.data
