"""Add baselines table for per-target drift tracking (Milestone 21).

Idempotent: create_all() (which runs before migrations at startup)
already creates new model tables, so only create what is missing.
"""
from alembic import op
import sqlalchemy as sa

revision = 'a1b2c3d4e5f6'
down_revision = '3c1e7a4b9d20'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    tables = [r[0] for r in conn.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='table'")]
    if "baselines" not in tables:
        op.create_table(
            'baselines',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('target', sa.String(length=255), nullable=False,
                      unique=True),
            sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scans.id'),
                      nullable=False),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'),
                      nullable=True),
            sa.Column('note', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )


def downgrade():
    op.drop_table('baselines')
