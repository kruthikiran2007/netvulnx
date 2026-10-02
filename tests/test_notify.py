"""Tests for webhook notifications (Milestone 16)."""
import tempfile

import pytest

from app import create_app, db
from app.models import ScheduledScan, Scan, Finding
from scanner import notify as notify_lib
from config import Config


@pytest.fixture()
def app_ctx():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    app = create_app(_TestConfig)
    app.config.update(TESTING=True)
    with app.app_context():
        yield app


def _scheduled_scan(app, webhook_url="https://hooks.example/x"):
    sched = ScheduledScan(name="nightly", target_raw="127.0.0.1",
                          target_type="ip", ports_raw="80", profile="quick",
                          interval="daily",
                          next_run_at=db.func.now(), enabled=True,
                          created_by="admin", webhook_url=webhook_url)
    db.session.add(sched)
    db.session.flush()
    scan = Scan(name="nightly (scheduled)", target_raw="127.0.0.1",
                target_type="ip", ports_raw="80", profile="quick",
                status="completed", schedule_id=sched.id, risk_score=3)
    db.session.add(scan)
    db.session.flush()
    db.session.add(Finding(scan_id=scan.id, asset_id=1, rule_id="a",
                           title="New thing", severity="high",
                           confidence="likely"))
    db.session.commit()
    return scan


def test_notification_sent_with_drift_summary(app_ctx):
    calls = []

    def fake_post(url, payload):
        calls.append((url, payload))
        return 200

    scan = _scheduled_scan(app_ctx)
    assert notify_lib.notify_scan_completed(scan, _post=fake_post) is True
    assert len(calls) == 1
    url, payload = calls[0]
    assert url == "https://hooks.example/x"
    assert payload["scan_id"] == scan.id
    assert payload["new_findings"] == 1  # no previous run: everything is new
    assert payload["top_new"][0]["title"] == "New thing"
    assert "NetVulnX" in payload["text"]


def test_no_webhook_no_notification(app_ctx):
    calls = []
    scan = _scheduled_scan(app_ctx, webhook_url=None)
    assert notify_lib.notify_scan_completed(
        scan, _post=lambda u, p: calls.append((u, p))) is False
    assert calls == []


def test_manual_scan_never_notifies(app_ctx):
    calls = []
    scan = Scan(name="one-off", target_raw="127.0.0.1", target_type="ip",
                ports_raw="80", profile="quick", status="completed")
    db.session.add(scan)
    db.session.commit()
    assert notify_lib.notify_scan_completed(
        scan, _post=lambda u, p: calls.append((u, p))) is False
    assert calls == []


def test_dead_webhook_does_not_raise(app_ctx):
    def boom(url, payload):
        raise OSError("webhook down")

    scan = _scheduled_scan(app_ctx)
    assert notify_lib.notify_scan_completed(scan, _post=boom) is False
