"""Database models — the shape of our stored data.

Each class below becomes a TABLE in the SQLite database, each object becomes
a ROW. SQLAlchemy translates between these Python classes and SQL for us, so
we never hand-write SQL (which also protects us from SQL injection).
"""
from datetime import datetime, timezone

from app import db


def _utcnow():
    return datetime.now(timezone.utc)


class Scan(db.Model):
    """One assessment run against a target."""
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default="Untitled scan")

    # Exactly what the user typed, plus how we classified it.
    target_raw = db.Column(db.String(255), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)  # 'ip', 'cidr' or 'hostname'
    ports_raw = db.Column(db.String(120), nullable=False)  # e.g. "80,443,22"

    # Lifecycle: draft -> awaiting_authorization -> running -> completed | failed
    # (cancelled if the user declines at the authorization gate)
    status = db.Column(db.String(20), nullable=False, default="draft")

    # The authorization gate: nothing runs until the user explicitly confirms.
    authorized = db.Column(db.Boolean, nullable=False, default=False)
    authorized_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    # Real progress (0-100): hosts completed / total hosts. Never faked.
    progress = db.Column(db.Integer, nullable=False, default=0)
    current_stage = db.Column(db.String(80), default="")
    error = db.Column(db.Text)

    # One scan has many assets; deleting a scan deletes its assets too.
    assets = db.relationship("Asset", backref="scan", cascade="all, delete-orphan")


class Asset(db.Model):
    """One host observed during a scan."""
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255))
    is_reachable = db.Column(db.Boolean, nullable=False, default=False)
    latency_ms = db.Column(db.Float)  # TCP connect round-trip time, when reachable
    open_ports_observed = db.Column(db.String(255), default="")  # e.g. "80,443"
    checked_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
