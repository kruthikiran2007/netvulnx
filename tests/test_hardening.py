# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for login hardening (Milestone 13): brute-force lockout,
password change, and secure cookie settings."""
import re
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from app import create_app, db
from app.models import User, AuditEvent, LoginThrottle
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


def _try_login(client, username="admin", password="wrongpass"):
    tok = _token(client, "/login")
    return client.post("/login", data={"_csrf_token": tok,
                                       "username": username,
                                       "password": password})


def _anon(app, client):
    """Fresh anonymous client: _setup_admin leaves `client` logged in, and
    /login redirects logged-in users, so brute-force attempts need this."""
    _setup_admin(client)
    return app.test_client()


# --- brute-force lockout --------------------------------------------------------

def test_five_failures_lock_the_account(app_and_client):
    app, client = app_and_client
    client = _anon(app, client)
    for _ in range(5):
        r = _try_login(client)
        assert r.status_code == 401
    # 6th attempt — even with the RIGHT password — is refused.
    r = _try_login(client, password="testpass123")
    assert r.status_code == 429
    assert b"Too many failed attempts" in r.data


def test_lockout_expires(app_and_client):
    app, client = app_and_client
    client = _anon(app, client)
    for _ in range(5):
        _try_login(client)
    with app.app_context():
        row = LoginThrottle.query.one()
        row.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()
    r = _try_login(client, password="testpass123")
    assert r.status_code == 302  # logged in again


def test_successful_login_clears_failures(app_and_client):
    app, client = app_and_client
    client = _anon(app, client)
    for _ in range(3):
        _try_login(client)
    _try_login(client, password="testpass123")
    with app.app_context():
        assert LoginThrottle.query.count() == 0


def test_lockout_is_audit_logged(app_and_client):
    app, client = app_and_client
    client = _anon(app, client)
    for _ in range(6):
        _try_login(client)
    with app.app_context():
        assert AuditEvent.query.filter_by(action="login.locked").count() >= 1


# --- password change ------------------------------------------------------------

def _change(client, current, new):
    tok = _token(client, "/account/password")
    return client.post("/account/password",
                       data={"_csrf_token": tok,
                             "current_password": current,
                             "new_password": new})


def test_password_change_happy_path(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    r = _change(client, "testpass123", "brandnewpass456")
    assert r.status_code == 302
    with app.app_context():
        assert AuditEvent.query.filter_by(action="password.changed").count() == 1
    # Old password dead, new password works.
    client.post("/logout", data={"_csrf_token": _token(client, "/")})
    assert _try_login(client, password="testpass123").status_code == 401
    assert _try_login(client, password="brandnewpass456").status_code == 302


def test_password_change_needs_current_password(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    r = _change(client, "notmyrealpassword", "brandnewpass456")
    assert r.status_code == 401
    # ...and the real password still works (anonymous client).
    anon = app.test_client()
    assert _try_login(anon, password="testpass123").status_code == 302


def test_password_change_rejects_short_and_same(app_and_client):
    _, client = app_and_client
    _setup_admin(client)
    assert _change(client, "testpass123", "short").status_code == 400
    assert _change(client, "testpass123", "testpass123").status_code == 400


# --- cookie settings --------------------------------------------------------------

def test_secure_cookie_defaults(app_and_client):
    app, _ = app_and_client
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    # Off by default (localhost HTTP); enabled via env var in deployment.
    assert app.config["SESSION_COOKIE_SECURE"] is False
