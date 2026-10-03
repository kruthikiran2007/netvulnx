# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Database migrations at startup (Milestone 12).

How schema changes work now:
  1. ``db.create_all()`` creates any missing TABLES (safe, idempotent).
  2. ``_ensure_columns()`` keeps pre-Alembic databases working: it adds
     columns that create_all() can't. Retained as a legacy sync — all NEW
     schema changes go through Alembic migrations instead.
  3. ``run_migrations()`` below: if the database has no ``alembic_version``
     table, it is STAMPED at head (the database already matches the models
     thanks to steps 1-2), otherwise it is UPGRADED to head. Either way the
     database ends up at the latest revision without ever losing data.

To add a schema change in the future:
  ./venv/bin/alembic -c migrations/alembic.ini revision --autogenerate -m "what changed"
then review the generated file in migrations/versions/ before committing.
"""
import os

from alembic import command
from alembic.config import Config as AlembicConfig


def run_migrations(app):
    cfg = AlembicConfig()
    cfg.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(app.root_path), "migrations"))
    cfg.set_main_option("sqlalchemy.url",
                        app.config["SQLALCHEMY_DATABASE_URI"])

    from app import db
    with app.app_context():
        inspector = db.inspect(db.engine)
        if not inspector.has_table("alembic_version"):
            # Pre-Alembic database (or brand-new one from create_all): its
            # schema already matches the models, so mark it current instead
            # of replaying the initial migration over existing tables.
            command.stamp(cfg, "head")
            app.logger.info("migrations: stamped existing database at head")
        else:
            command.upgrade(cfg, "head")
            app.logger.info("migrations: upgraded database to head")
