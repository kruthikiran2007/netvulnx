"""Tests for authentication, the login gate, and the audit log (Milestone 8).

Uses throwaway SQLite databases — never the dev database.
"""
import re
import tempfile

import pytest

from app import create_app, db
from app.models import User, AuditEvent
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
    return r


def _login(client, username="admin", password="testpass123"):
    tok = _token(client, "/login")
    return client.post("/login", data={"_csrf_token": tok, "username": username,
                                       "password": password})


# --- first-run setup --------------------------------------------------------

def test_no_users_redirects_to_setup(app_and_client):
    _, client = app_and_client
    assert client.get("/").status_code == 302
    assert client.get("/").headers["Location"].endswith("/setup")
    assert client.get("/scans/new").headers["Location"].endswith("/setup")


def test_setup_creates_admin_and_logs_in(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        assert user is not None
        assert user.is_admin is True
        assert user.password_hash != "testpass123"  # never plaintext
    # logged in: dashboard renders
    assert client.get("/").status_code == 200


def test_setup_rejected_when_users_exist(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    assert client.get("/setup").status_code == 302  # -> login
    with app.test_client() as anon:  # anonymous second attempt
        tok = _token(anon, "/login")
        r = anon.post("/setup", data={"_csrf_token": tok, "username": "evil",
                                      "password": "testpass123"})
        assert r.status_code == 403


def test_setup_validates_input(app_and_client):
    _, client = app_and_client
    tok = _token(client, "/setup")
    r = client.post("/setup", data={"_csrf_token": tok, "username": "ab",
                                    "password": "testpass123"})
    assert r.status_code == 400
    tok = _token(client, "/setup")
    r = client.post("/setup", data={"_csrf_token": tok, "username": "admin",
                                    "password": "short"})
    assert r.status_code == 400


# --- login / logout ----------------------------------------------------------

def test_login_flow(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    # log out via a fresh (anonymous) client on the same app
    with app.test_client() as anon:
        r = anon.get("/")
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]
        # wrong password
        r = _login(anon, password="wrongpass1")
        assert r.status_code == 401
        assert anon.get("/").status_code == 302
        # right password
        r = _login(anon)
        assert r.status_code == 302
        assert anon.get("/").status_code == 200


def test_login_next_redirect_is_safe(app_and_client):
    _, client = app_and_client
    _setup_admin(client)
    with client.application.test_client() as anon:
        tok = _token(anon, "/login")
        r = anon.post("/login", data={"_csrf_token": tok, "username": "admin",
                                      "password": "testpass123",
                                      "next": "https://evil.example/"})
        assert r.status_code == 302
        assert r.headers["Location"].endswith("/")


def test_logout_ends_session(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    tok = _token(client, "/")
    r = client.post("/logout", data={"_csrf_token": tok})
    assert r.status_code == 302
    assert client.get("/").status_code == 302  # gated again


def test_api_status_is_gated(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    with app.test_client() as anon:
        assert anon.get("/api/scans/1/status").status_code == 302


# --- audit log ----------------------------------------------------------------

def test_audit_records_auth_and_scan_events(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    with app.test_client() as anon:
        _login(anon, password="wrongpass1")  # failed attempt, anonymous
    tok = _token(client, "/scans/new")
    client.post("/scans/new", data={"_csrf_token": tok, "name": "t",
                                    "target": "127.0.0.1",
                                    "profile": "custom", "ports": "80"})
    with app.app_context():
        actions = [e.action for e in
                   AuditEvent.query.order_by(AuditEvent.id).all()]
    assert "user.created" in actions
    assert "login.failed" in actions
    assert "scan.created" in actions


def test_audit_page_requires_admin(app_and_client):
    app, client = app_and_client
    _setup_admin(client, username="boss")
    # create a non-admin directly
    with app.app_context():
        from app import auth as auth_lib
        db.session.add(User(username="pleb",
                            password_hash=auth_lib.hash_password("testpass123"),
                            role="viewer"))
        db.session.commit()
    with app.test_client() as anon:
        _login(anon, username="pleb")
        assert anon.get("/audit").status_code == 403
    assert client.get("/audit").status_code == 200  # boss is admin


def test_passwords_are_salted_hashes(app_and_client):
    app, client = app_and_client
    _setup_admin(client, username="user1", password="samepassword1")
    # second user, same password -> different hash (salt works)
    with app.app_context():
        from app import auth as auth_lib
        db.session.add(User(username="user2",
                            password_hash=auth_lib.hash_password("samepassword1")))
        db.session.commit()
        h1 = User.query.filter_by(username="user1").first().password_hash
        h2 = User.query.filter_by(username="user2").first().password_hash
        assert h1 != h2
        assert auth_lib.verify_password(
            User.query.filter_by(username="user1").first(), "samepassword1")
        assert not auth_lib.verify_password(
            User.query.filter_by(username="user1").first(), "nope")
