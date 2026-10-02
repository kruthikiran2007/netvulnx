"""Tests for the email password-reset flow (Milestone 20).

Uses throwaway SQLite databases and a fake SMTP outbox — no real email
is ever sent.
"""
import re
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from app import create_app, db
from app.models import User, PasswordResetToken
from app import auth as auth_lib
from app import mail as mail_lib
from config import Config


@pytest.fixture()
def app_and_client(monkeypatch):
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    outbox = []

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name
        SMTP_ENABLED = True
        SMTP_HOST = "fake"
        SMTP_FROM = "netvulnx@test.local"

    def fake_send(to, username, reset_url):
        outbox.append({"to": to, "username": username, "url": reset_url})
        return True, ""

    monkeypatch.setattr(mail_lib, "send_password_reset", fake_send)
    app = create_app(_TestConfig)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield app, c, outbox


def _token(client, url):
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="_csrf_token" value="([^"]+)"', html)
    assert m, f"no CSRF token on {url}"
    return m.group(1)


def _make_user(app, username="analyst", email="analyst@test.local"):
    with app.app_context():
        u = User(username=username,
                 password_hash=auth_lib.hash_password("old-password-1"),
                 role="operator", email=email)
        db.session.add(u)
        db.session.commit()
        return u.id


def _request_reset(client, username):
    tok = _token(client, "/forgot-password")
    return client.post("/forgot-password",
                       data={"_csrf_token": tok, "username": username})


def test_reset_link_emailed_and_usable(app_and_client):
    app, client, outbox = app_and_client
    _make_user(app)
    r = _request_reset(client, "analyst")
    assert r.status_code == 200
    assert len(outbox) == 1
    assert outbox[0]["to"] == "analyst@test.local"
    raw = outbox[0]["url"].rsplit("/", 1)[-1]

    # Only the hash is stored — the raw secret never touches the database.
    with app.app_context():
        rec = PasswordResetToken.query.first()
        assert rec is not None
        assert raw not in rec.token_hash
        assert rec.is_valid

    # Use the link: set a new password.
    tok = _token(client, f"/reset-password/{raw}")
    r = client.post(f"/reset-password/{raw}",
                    data={"_csrf_token": tok,
                          "new_password": "brand-new-pass-2"})
    assert r.status_code == 302
    with app.app_context():
        u = User.query.filter_by(username="analyst").first()
        assert auth_lib.verify_password(u, "brand-new-pass-2")
        rec = PasswordResetToken.query.first()
        assert not rec.is_valid  # single-use: burned

    # Replaying the same link fails.
    r = client.post(f"/reset-password/{raw}",
                    data={"_csrf_token": _token(client, "/forgot-password"),
                          "new_password": "another-pass-3"})
    assert r.status_code == 401


def test_no_user_enumeration(app_and_client):
    app, client, outbox = app_and_client
    _make_user(app)
    real = _request_reset(client, "analyst").get_data(as_text=True)
    ghost = _request_reset(client, "no-such-user").get_data(as_text=True)
    # Same message whether the account exists or not; nothing emailed.
    assert "is on its way" in real
    assert "is on its way" in ghost
    assert len(outbox) == 1  # only the real account got an email


def test_no_email_no_link(app_and_client):
    app, client, outbox = app_and_client
    _make_user(app, username="noemail", email=None)
    r = _request_reset(client, "noemail")
    assert "is on its way" in r.get_data(as_text=True)
    assert len(outbox) == 0  # nowhere to send it — and we don't say so


def test_expired_token_rejected(app_and_client):
    app, client, outbox = app_and_client
    _make_user(app)
    _request_reset(client, "analyst")
    raw = outbox[0]["url"].rsplit("/", 1)[-1]
    with app.app_context():
        rec = PasswordResetToken.query.first()
        rec.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
    tok = _token(client, "/forgot-password")
    r = client.post(f"/reset-password/{raw}",
                    data={"_csrf_token": tok, "new_password": "x" * 12})
    assert r.status_code == 401
    with app.app_context():
        u = User.query.filter_by(username="analyst").first()
        assert auth_lib.verify_password(u, "old-password-1")  # unchanged


def test_rate_limited_requests(app_and_client):
    app, client, outbox = app_and_client
    _make_user(app)
    for _ in range(Config.RESET_MAX_PER_HOUR + 3):
        _request_reset(client, "analyst")
    assert len(outbox) == Config.RESET_MAX_PER_HOUR


def test_smtp_disabled_shows_notice(app_and_client):
    app, client, outbox = app_and_client
    app.config["SMTP_ENABLED"] = False
    html = client.get("/forgot-password").get_data(as_text=True)
    assert "not enabled" in html


def test_user_can_set_own_email(app_and_client):
    app, client, outbox = app_and_client
    uid = _make_user(app, username="admin2", email=None)
    with app.app_context():
        u = User.query.get(uid)
        u.role = "admin"
        db.session.commit()
    tok = _token(client, "/login")
    client.post("/login", data={"_csrf_token": tok, "username": "admin2",
                                "password": "old-password-1"})
    tok = _token(client, "/account/password")
    r = client.post("/account/email",
                    data={"_csrf_token": tok, "email": "me@test.local"})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.get(uid).email == "me@test.local"
