"""Flask application factory.

An "app factory" is just a function that builds and returns the Flask app.
Why a function instead of a ready-made global object? Because tests (and the
dev server, and future scripts) can each build a fresh app whenever they want,
without side effects leaking between them.
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# The database handle. Models (in app/models.py) attach their tables to this.
db = SQLAlchemy()


def create_app(config_class=None):
    app = Flask(__name__)

    if config_class is None:
        from config import Config
        config_class = Config
    app.config.from_object(config_class)

    db.init_app(app)

    # Register all web pages / actions.
    from app import routes
    app.register_blueprint(routes.bp)

    # --- Hardening (Milestone 7) ---
    from app import csrf as _csrf

    @app.context_processor
    def _inject_csrf():
        # Makes {{ csrf_token() }} available in every template.
        return {"csrf_token": _csrf.get_token}

    @app.context_processor
    def _inject_user():
        # Makes {{ current_user }} available in every template (None when
        # logged out) so the nav can show login/logout state.
        from app import auth as _auth
        return {"current_user": _auth.current_user()}

    @app.before_request
    def _check_csrf():
        # Every POST must carry this session's CSRF token.
        from flask import request as _request
        if _request.method == "POST":
            _csrf.validate_csrf()

    @app.before_request
    def _require_login():
        """Login gate (Milestone 8): every page needs an authenticated user.

        /login, /setup and static files are exempt. With no accounts yet,
        everything redirects to /setup so the first admin can be created.
        """
        from flask import request as _request, redirect as _redirect, \
            url_for as _url_for
        from app import auth as _auth
        from app.models import User as _User
        path = _request.path
        if path.startswith("/static/") or path in ("/login", "/setup"):
            return None
        if _User.query.count() == 0:
            return _redirect(_url_for("main.setup"))
        if not _auth.current_user():
            nxt = path if path.startswith("/") and not path.startswith("//") \
                else "/"
            return _redirect(_url_for("main.login", next=nxt))
        return None

    @app.after_request
    def _security_headers(response):
        # Cheap, safe defaults. The CSP allows our own inline scripts and
        # the Chart.js CDN; everything else stays same-origin.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'")
        return response

    # Harden the session cookie. (Flask's own default leaves SameSite unset,
    # so setdefault would be a no-op — set it unless already configured.
    # Secure=true needs HTTPS, which the local dev server doesn't have —
    # see SECURITY.md.)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    if app.config.get("SECRET_KEY") == "dev-only-change-me":
        app.logger.warning(
            "Using the DEVELOPMENT secret key — set the NETVULNX_SECRET_KEY "
            "environment variable before exposing this app to anyone else.")

    # Template filter: parse JSON stored in text columns (redirect chains,
    # header lists, check details) back into lists/dicts for rendering.
    import json as _json

    @app.template_filter("fromjson")
    def _fromjson(value):
        if not value:
            return None
        try:
            return _json.loads(value)
        except (TypeError, ValueError):
            return None

    # Create database tables on first run. (Later milestones will switch to
    # proper database migrations; create_all is fine while the schema is young.)
    with app.app_context():
        db.create_all()
        _ensure_columns(app)

    # Crash recovery: scans left "running" by a previous process must not
    # stay stuck forever — mark them interrupted, honestly.
    from scanner import jobs
    jobs.recover_interrupted(app)

    return app


def _ensure_columns(app):
    """Add columns that create_all() can't: it creates missing TABLES but
    never alters existing ones, so a dev database from an earlier milestone
    would otherwise be missing new columns (and crash). Each entry is
    (table, column, sqlite_type). Runs on every startup; cheap and idempotent.
    """
    new_columns = [
        ("scans", "risk_score", "INTEGER NOT NULL DEFAULT 0"),
        ("findings", "status", "VARCHAR(20) NOT NULL DEFAULT 'open'"),
        ("findings", "status_note", "TEXT"),
        ("findings", "status_updated_at", "DATETIME"),
    ]
    with db.engine.connect() as conn:
        for table, column, ctype in new_columns:
            existing = [r[1] for r in
                        conn.exec_driver_sql(f"PRAGMA table_info({table})")]
            if column not in existing:
                conn.exec_driver_sql(
                    f"ALTER TABLE {table} ADD COLUMN {column} {ctype}")
                app.logger.info("schema: added column %s.%s", table, column)
        conn.commit()
