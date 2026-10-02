"""Tests for Alembic migrations (Milestone 12).

Uses throwaway SQLite databases — never the dev database.
"""
import tempfile

from app import create_app, db
from app import migrations as migrations_lib
from config import Config


def _make_app():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    return create_app(_TestConfig), tmp.name


def _version(app):
    with app.app_context():
        return db.session.execute(
            db.text("SELECT version_num FROM alembic_version")).scalar()


def test_fresh_database_stamped_at_head():
    app, _ = _make_app()
    assert _version(app) == "3c1e7a4b9d20"


def test_migrations_idempotent_on_restart():
    app, path = _make_app()
    assert _version(app) == "3c1e7a4b9d20"

    class _TestConfig2(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + path

    app2 = create_app(_TestConfig2)
    assert _version(app2) == "3c1e7a4b9d20"
    # Tables still all there after the second startup.
    with app2.app_context():
        tables = db.inspect(db.engine).get_table_names()
    assert "alembic_version" in tables
    assert "scheduled_scans" in tables


def test_pre_alembic_database_gets_stamped_not_replayed():
    """A database with the full schema but no alembic_version is stamped at
    head — the initial migration must NOT run create_table over existing
    tables, and existing rows must survive."""
    from sqlalchemy import create_engine
    import app.models  # noqa: F401 — registers tables on db.metadata
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    # Exactly what a pre-Alembic app produced: create_all() schema, no
    # version table, plus a real row.
    engine = create_engine("sqlite:///" + tmp.name)
    db.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(db.text(
            "INSERT INTO scans (name, target_raw, target_type, ports_raw,"
            " profile, status, authorized, created_at, progress, risk_score)"
            " VALUES ('legacy', '127.0.0.1', 'ip', '80', 'quick',"
            " 'completed', 0, '2026-01-01 00:00:00', 100, 0)"))
    engine.dispose()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    app = create_app(_TestConfig)
    assert _version(app) == "3c1e7a4b9d20"
    with app.app_context():
        name = db.session.execute(
            db.text("SELECT name FROM scans WHERE target_raw='127.0.0.1'")
        ).scalar()
        assert name == "legacy"  # data survived
