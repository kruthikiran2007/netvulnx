"""Tests for CSV/JSON exports (Milestone 11)."""
import csv
import io
import json
import re
import tempfile

import pytest

from app import create_app, db
from app.models import Scan, Finding
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


def _scan_with_findings(app):
    with app.app_context():
        scan = Scan(name="export me", target_raw="127.0.0.1",
                    target_type="ip", ports_raw="80", profile="quick",
                    status="completed", risk_score=5)
        db.session.add(scan)
        db.session.flush()
        db.session.add_all([
            Finding(scan_id=scan.id, asset_id=1, rule_id="a",
                    title="Critical thing", severity="critical",
                    confidence="confirmed", status="open"),
            Finding(scan_id=scan.id, asset_id=1, rule_id="b",
                    title="Info thing", severity="info",
                    confidence="informational", status="acknowledged"),
        ])
        db.session.commit()
        return scan.id


def test_csv_export(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    sid = _scan_with_findings(app)
    r = client.get(f"/scans/{sid}/export.csv")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert "attachment" in r.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
    assert len(rows) == 2
    # Most severe first.
    assert rows[0]["severity"] == "critical"
    assert rows[0]["title"] == "Critical thing"
    assert rows[1]["status"] == "acknowledged"
    assert set(rows[0]) >= {"finding_id", "rule_id", "description",
                            "remediation", "references"}


def test_json_export(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    sid = _scan_with_findings(app)
    r = client.get(f"/scans/{sid}/export.json")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    assert "attachment" in r.headers["Content-Disposition"]
    data = json.loads(r.get_data(as_text=True))
    assert data["scan"]["id"] == sid
    assert data["scan"]["target"] == "127.0.0.1"
    assert data["scan"]["risk_score"] == 5
    assert len(data["findings"]) == 2
    assert data["exported_by"] == "NetVulnX"


def test_exports_require_login(app_and_client):
    app, client = app_and_client
    sid = _scan_with_findings(app)
    assert client.get(f"/scans/{sid}/export.csv").status_code == 302
    assert client.get(f"/scans/{sid}/export.json").status_code == 302


def test_export_missing_scan_404(app_and_client):
    _, client = app_and_client
    _setup_admin(client)
    assert client.get("/scans/9999/export.csv").status_code == 404
    assert client.get("/scans/9999/export.json").status_code == 404
