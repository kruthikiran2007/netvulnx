# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Minimal CSRF protection (no extra dependencies).

How it works: when a page with a form is rendered, the template calls
``{{ csrf_token() }}``, which creates (once per browser session) a random
token stored in the signed session cookie. Every POST form includes that
token as a hidden field; ``validate_csrf()`` runs before each POST and
rejects the request with 403 if the token is missing or wrong.

Why this stops CSRF: an attacker's site can make *your browser* submit a
form to NetVulnX, but it cannot read the token (same-origin policy), so
the forged request fails validation. GET requests never change anything,
so they need no token.
"""
import hmac
import secrets

from flask import abort, request, session


def get_token():
    """Return this session's CSRF token, creating it on first use."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    """Abort with 403 unless the POST carries this session's token."""
    expected = session.get("_csrf_token", "")
    submitted = request.form.get("_csrf_token", "")
    if not expected or not hmac.compare_digest(expected, submitted):
        abort(403, description=(
            "Missing or invalid CSRF token. Please go back, reload the "
            "page, and try again."))
