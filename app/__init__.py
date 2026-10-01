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
