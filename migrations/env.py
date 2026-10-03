# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Alembic environment: run migrations against the app's database.

The app package is imported ONLY for db.metadata — create_app() is never
called here, so there is no recursion with app/migrations.py (which drives
Alembic programmatically at startup).

The database URL comes from, in order:
  1. `alembic -x url=<sqlalchemy url>` on the CLI (used for autogenerate),
  2. the sqlalchemy.url set programmatically by app/migrations.py,
  3. the fallback in migrations/alembic.ini.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic import context  # noqa: E402
from sqlalchemy import engine_from_config  # noqa: E402

from app import db  # noqa: E402  (metadata only — no app is created)
import app.models  # noqa: E402,F401  (registers all tables on db.metadata)

config = context.config
target_metadata = db.metadata


def _database_url():
    x_args = context.get_x_argument(as_dictionary=True)
    if x_args.get("url"):
        return x_args["url"]
    return config.get_main_option("sqlalchemy.url")


def run_migrations_online():
    url = _database_url()
    connectable = engine_from_config({"sqlalchemy.url": url},
                                     prefix="sqlalchemy.")
    with connectable.connect() as connection:
        context.configure(connection=connection,
                          target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
