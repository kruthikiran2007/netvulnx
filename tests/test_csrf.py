"""Tests for CSRF protection and security headers (Milestone 7).

Uses a throwaway SQLite database — never the dev database.
"""
import re
import tempfile

import pytest

from app import create_app
from config import Config


@pytest.fixture()
def client():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    app = create_app(_TestConfig)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        # Milestone 8: all pages sit behind the login gate, so create the
        # first admin through the real /setup flow before testing.
        html = c.get("/setup").get_data(as_text=True)
        tok = re.search(r'name="_csrf_token" value="([^"]+)"', html).group(1)
        r = c.post("/setup", data={"_csrf_token": tok, "username": "admin",
                                   "password": "testpass123"})
        assert r.status_code == 302
        yield c


def _token_from(client, url="/scans/new"):
    """Render a form page and pull the CSRF token out of it."""
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="_csrf_token" value="([^"]+)"', html)
    assert m, "no CSRF token in form"
    return m.group(1)


def test_form_contains_csrf_token(client):
    html = client.get("/scans/new").get_data(as_text=True)
    assert 'name="_csrf_token"' in html


def test_post_without_token_is_rejected(client):
    r = client.post("/scans/new", data={
        "name": "x", "target": "127.0.0.1", "profile": "custom",
        "ports": "80"})
    assert r.status_code == 403


def test_post_with_wrong_token_is_rejected(client):
    _token_from(client)  # establish a real session/token first
    r = client.post("/scans/new", data={
        "name": "x", "target": "127.0.0.1", "profile": "custom",
        "ports": "80", "_csrf_token": "forged"})
    assert r.status_code == 403


def test_post_with_valid_token_works(client):
    token = _token_from(client)
    r = client.post("/scans/new", data={
        "name": "csrf e2e", "target": "127.0.0.1", "profile": "custom",
        "ports": "80", "_csrf_token": token})
    assert r.status_code == 302  # scan created -> authorize page


def test_token_is_per_session(client):
    t1 = _token_from(client)
    with client.session_transaction() as sess:
        sess.clear()  # drop the session -> new visitor (logged out)
    # Anonymous visitors can't reach /scans/new (login gate), so take the
    # token from the login form instead — still a per-session token.
    t2 = _token_from(client, url="/login")
    assert t1 != t2


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "same-origin"
    csp = r.headers["Content-Security-Policy"]
    assert "cdn.jsdelivr.net" in csp and "object-src 'none'" in csp


def test_session_cookie_flags(client):
    r = client.get("/scans/new")  # a form page creates the session + token
    set_cookie = r.headers.get("Set-Cookie", "")
    assert "session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie
