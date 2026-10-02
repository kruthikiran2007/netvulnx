"""password reset tokens + user email

Revision ID: 3c1e7a4b9d20
Revises: fe152a39d862
Create Date: 2026-10-02 09:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '3c1e7a4b9d20'
down_revision = 'fe152a39d862'
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent: create_all() (which runs before migrations at startup)
    # already creates new model tables, and _ensure_columns() already adds
    # the email column — so only do what is still missing. Without these
    # guards, upgrading a database from the previous head would crash.
    conn = op.get_bind()
    tables = [r[0] for r in conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'")]
    cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)")]
    if "email" not in cols:
        op.add_column('users',
                      sa.Column('email', sa.String(length=255), nullable=True))
    if "password_reset_tokens" not in tables:
        op.create_table(
            'password_reset_tokens',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'),
                      nullable=False),
            sa.Column('token_hash', sa.String(length=64), nullable=False,
                      unique=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('used_at', sa.DateTime(), nullable=True),
        )


def downgrade():
    op.drop_table('password_reset_tokens')
    op.drop_column('users', 'email')
