"""Tests for team roles (Milestone 15): viewer / operator / admin."""
import re
import tempfile

import pytest

from app import create_app, db
from app.models import User
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


def _setup_admin(client):
    tok = _token(client, "/setup")
    client.post("/setup", data={"_csrf_token": tok, "username": "admin",
                                "password": "testpass123"})


def _make_user(app, username, role, password="userpass123"):
    with app.app_context():
        u = User(username=username,
                 password_hash=auth_lib.hash_password(password), role=role)
        db.session.add(u)
        db.session.commit()


def _login_as(client, username, password="userpass123"):
    tok = _token(client, "/login")
    r = client.post("/login", data={"_csrf_token": tok, "username": username,
                                    "password": password})
    assert r.status_code == 302


def _logout(client):
    client.post("/logout", data={"_csrf_token": _token(client, "/")})


# --- role helper ----------------------------------------------------------------

def test_has_role_ranking():
    assert auth_lib.has_role(None, "viewer") is False

    class U:
        def __init__(self, role):
            self.role = role

    assert auth_lib.has_role(U("viewer"), "viewer")
    assert not auth_lib.has_role(U("viewer"), "operator")
    assert auth_lib.has_role(U("operator"), "viewer")
    assert auth_lib.has_role(U("operator"), "operator")
    assert not auth_lib.has_role(U("operator"), "admin")
    assert auth_lib.has_role(U("admin"), "viewer")
    assert auth_lib.has_role(U("admin"), "admin")
    assert not auth_lib.has_role(U("nonsense"), "viewer")


# --- user management --------------------------------------------------------------

def test_admin_can_create_users(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    tok = _token(client, "/users")
    r = client.post("/users/new", data={"_csrf_token": tok,
                                        "username": "op1",
                                        "password": "oppass123",
                                        "role": "operator"})
    assert r.status_code == 302
    with app.app_context():
        u = User.query.filter_by(username="op1").one()
        assert u.role == "operator"
        assert not u.is_admin


def test_cannot_demote_or_delete_last_admin(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
    tok = _token(client, "/users")
    # Demote self -> refused.
    r = client.post(f"/users/{admin_id}/role",
                    data={"_csrf_token": tok, "role": "viewer"})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.get(admin_id).role == "admin"
    # Delete self -> refused.
    tok = _token(client, "/users")
    client.post(f"/users/{admin_id}/delete", data={"_csrf_token": tok})
    with app.app_context():
        assert User.query.get(admin_id) is not None


# --- viewer restrictions ------------------------------------------------------------

def test_viewer_is_read_only(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    _make_user(app, "viewer", "viewer")
    _logout(client)
    _login_as(client, "viewer")

    # Reads work.
    assert client.get("/").status_code == 200
    assert client.get("/scans").status_code == 200

    # Writes are forbidden.
    tok = _token(client, "/")
    assert client.post("/scans/new", data={"_csrf_token": tok}).status_code == 403
    assert client.get("/scans/new").status_code == 403
    assert client.get("/schedules/new").status_code == 403
    assert client.get("/settings/tokens").status_code == 403
    assert client.get("/users").status_code == 403
    assert client.get("/audit").status_code == 403


# --- operator powers ------------------------------------------------------------------

def test_operator_can_scan_but_not_administer(app_and_client):
    app, client = app_and_client
    _setup_admin(client)
    _make_user(app, "op", "operator")
    _logout(client)
    _login_as(client, "op", "userpass123")

    # Operator reaches the scan form and schedule pages...
    assert client.get("/scans/new").status_code == 200
    assert client.get("/schedules").status_code == 200
    # ...but not admin pages.
    assert client.get("/users").status_code == 403
    assert client.get("/audit").status_code == 403
    assert client.get("/settings/tokens").status_code == 403
