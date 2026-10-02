"""Authentication and audit logging (Milestone 8).

Passwords: never stored. We keep only a salted hash made by Werkzeug's
``generate_password_hash`` (scrypt-based by default) and check login
attempts with ``check_password_hash``. There is no way to recover a
password from the hash — only to test guesses against it.

Sessions: after a successful login we store just the user's id in Flask's
signed session cookie. Every request looks the id up in the database, so
deleting the user (or the database) ends the session immediately.

Audit log: security-relevant actions are appended to the ``audit_events``
table — who, what, when, from which IP. The app never edits or deletes
these rows.
"""
from flask import request, session
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models import User, AuditEvent

#: Session key holding the logged-in user's id (nothing else).
SESSION_KEY = "user_id"


def hash_password(password):
    """Turn a plaintext password into a salted hash for storage."""
    return generate_password_hash(password)


def verify_password(user, password):
    """True if this password matches the user's stored hash."""
    if not user or not password:
        return False
    return check_password_hash(user.password_hash, password)


def current_user():
    """The logged-in User, or None. Looks up the session's id each time."""
    user_id = session.get(SESSION_KEY)
    if not user_id:
        return None
    return db.session.get(User, user_id)


def login_user(user):
    """Mark this browser session as logged in as ``user``."""
    session[SESSION_KEY] = user.id


def logout_user():
    """Forget the login for this browser session."""
    session.pop(SESSION_KEY, None)


def log_audit(action, detail="", actor=None):
    """Append one row to the audit log. Always safe to call: it commits
    on its own so callers don't have to think about transactions."""
    if actor is None:
        user = current_user()
        actor = user.username if user else "anonymous"
    try:
        ip = request.remote_addr
    except RuntimeError:  # no request context (background jobs)
        ip = None
    db.session.add(AuditEvent(actor=actor, action=action,
                              detail=detail or None, ip_address=ip))
    db.session.commit()


def valid_username(username):
    """Usernames: 3-40 chars, letters/digits/_/-. Simple and predictable."""
    if not username or not 3 <= len(username) <= 40:
        return False
    return all(c.isalnum() or c in "_-" for c in username)


def valid_password(password):
    """Minimum bar: at least 8 characters. (Length beats complexity.)"""
    return bool(password) and len(password) >= 8
