"""Tests for API tokens (Milestone 14)."""
import re
import tempfile

import pytest

from app import create_app, db
from app.models import ApiToken, AuditEvent
from app import auth as auth_lib
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


def _create_token(client, name="ci"):
    tok = _token(client, "/settings/tokens")
    r = client.post("/settings/tokens/new",
                    data={"_csrf_token": tok, "name": name},
                    follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["Location"]
    m = re.search(r"new_secret=([^&]+)", loc)
    assert m, "secret not shown after creation"
    return m.group(1)


def test_token_creation_shows_secret_once(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    secret = _create_token(client)
    assert secret.startswith("nvx_")
    with app.app_context():
        t = ApiToken.query.one()
        assert t.name == "ci"
        assert t.revoked is False
        # Plaintext is NOT stored — only the hash.
        assert t.token_hash == auth_lib.hash_token(secret)
        assert secret not in (t.token_hash, t.prefix)
        assert AuditEvent.query.filter_by(action="token.created").count() == 1
    # The list page afterwards does NOT show the secret.
    assert secret not in client.get("/settings/tokens").get_data(as_text=True)


def test_bearer_token_authenticates_api(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    secret = _create_token(client)
    with app.test_client() as anon:
        # No session — but the Bearer header gets us past the login gate.
        # (404, not 302, proves authentication succeeded.)
        r = anon.get("/api/scans/9999/status",
                     headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code == 404
        # And the token's last-used timestamp was recorded.
    with app.app_context():
        assert ApiToken.query.one().last_used_at is not None


def test_bearer_token_without_session_needs_no_csrf(app_and_client):
    _, client = app_and_client
    _setup_admin(client)
    secret = _create_token(client)
    with client.application.test_client() as anon:
        # POST without any CSRF token works with a valid Bearer header.
        r = anon.post("/api/scans/9999/cancel",
                      headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code in (404, 405)  # not 403/302


def test_revoked_token_rejected(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    secret = _create_token(client)
    with app.app_context():
        tid = ApiToken.query.one().id
    tok = _token(client, "/settings/tokens")
    client.post(f"/settings/tokens/{tid}/revoke",
                data={"_csrf_token": tok})
    with app.test_client() as anon:
        r = anon.get("/api/scans/9999/status",
                     headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code == 302  # back to the login gate
        assert "/login" in r.headers["Location"]


def test_wrong_token_rejected(app_and_client):
    _, client = app_and_client
    _setup_admin(client)
    with client.application.test_client() as anon:
        r = anon.get("/api/scans/1/status",
                     headers={"Authorization": "Bearer nvx_" + "0" * 32})
        assert r.status_code == 302
        r = anon.get("/api/scans/1/status")
        assert r.status_code == 302


def test_token_pages_require_admin(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    # A real non-admin user.
    with app.app_context():
        from app.models import User
        u = User(username="viewer",
                 password_hash=auth_lib.hash_password("viewerpass123"),
                 is_admin=False)
        db.session.add(u)
        db.session.commit()
    client.post("/logout", data={"_csrf_token": _token(client, "/")})
    tok = _token(client, "/login")
    r = client.post("/login", data={"_csrf_token": tok, "username": "viewer",
                                    "password": "viewerpass123"})
    assert r.status_code == 302  # logged in as viewer
    assert client.get("/settings/tokens").status_code == 403
    tok = _token(client, "/")
    assert client.post("/settings/tokens/new",
                       data={"_csrf_token": tok}).status_code == 403
