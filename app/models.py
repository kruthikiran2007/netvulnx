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

    # Scan profile: 'quick', 'standard', 'deep' or 'custom'. Defines behavior
    # (which ports, whether host discovery may skip silent hosts).
    profile = db.Column(db.String(20), nullable=False, default="custom")

    # Lifecycle: draft -> awaiting_authorization -> running
    #            -> completed | failed | cancelled | interrupted
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

    # Aggregate risk score (Milestone 4): sum of severity weights across the
    # scan's findings. See rules/scoring.py for the formula. 0 does not mean
    # "secure" — it means no rule matched.
    risk_score = db.Column(db.Integer, nullable=False, default=0)

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

    # One asset has many open ports (Milestone 2+).
    ports = db.relationship("Port", backref="asset", cascade="all, delete-orphan")


class TlsInfo(db.Model):
    """Read-only TLS handshake observations for one port.

    Raw facts (version, cipher, cert fields) plus a few deterministic
    derived flags (expired, self-signed). Risk JUDGMENTS belong to the
    rule engine (Milestone 4) — this table only records what we measured.
    """
    __tablename__ = "tls_info"

    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"),
                        nullable=False, unique=True)

    tls_version = db.Column(db.String(20))       # e.g. "TLSv1.3"
    cipher_name = db.Column(db.String(80))
    cipher_bits = db.Column(db.Integer)
    weak_cipher = db.Column(db.Boolean)          # weak by construction
    supports_tls10 = db.Column(db.Boolean)       # old-protocol probes
    supports_tls11 = db.Column(db.Boolean)
    supports_tls12 = db.Column(db.Boolean)

    cert_subject = db.Column(db.String(255))
    cert_issuer = db.Column(db.String(255))
    cert_sans = db.Column(db.Text)                # comma-joined
    cert_not_after = db.Column(db.DateTime)
    cert_expired = db.Column(db.Boolean)
    cert_self_signed = db.Column(db.Boolean)
    hostname_mismatch = db.Column(db.Boolean)     # cert doesn't cover target

    error = db.Column(db.Text)                    # if the handshake failed
    checked_at = db.Column(db.DateTime, nullable=False, default=_utcnow)


class HttpInfo(db.Model):
    """Read-only HTTP(S) observations for one port: redirects, headers,
    and page clues — the raw material the rule engine will judge later."""
    __tablename__ = "http_info"

    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"),
                        nullable=False, unique=True)

    scheme = db.Column(db.String(10))             # "http" / "https"
    final_url = db.Column(db.String(500))
    status_code = db.Column(db.Integer)
    redirect_chain = db.Column(db.Text)           # JSON list of hops

    server_header = db.Column(db.String(255))
    powered_by = db.Column(db.String(255))
    present_security_headers = db.Column(db.Text)  # JSON dict name->value
    missing_security_headers = db.Column(db.Text)  # JSON list

    redirects_to_https = db.Column(db.Boolean)
    page_title = db.Column(db.String(255))
    directory_listing = db.Column(db.Boolean)
    default_page = db.Column(db.String(120))      # e.g. "nginx default page"

    error = db.Column(db.Text)
    checked_at = db.Column(db.DateTime, nullable=False, default=_utcnow)


class ServiceCheck(db.Model):
    """One named, safe service observation for a port.

    check_type: 'dns_version' | 'smtp_ehlo' | 'ftp_anonymous'
    details: JSON with the check-specific evidence.
    """
    __tablename__ = "service_checks"

    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"), nullable=False)
    check_type = db.Column(db.String(40), nullable=False)
    summary = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text)                  # JSON
    checked_at = db.Column(db.DateTime, nullable=False, default=_utcnow)

    __table_args__ = (db.UniqueConstraint("port_id", "check_type",
                                         name="uq_port_check"),)


class Port(db.Model):
    """One OPEN port found on an asset, with its fingerprinted service.

    We store open ports only — closed/filtered ports are counted in the
    scan summary, not stored row by row. Every row carries the evidence
    (banner) and the confidence behind the service identification.
    """
    __tablename__ = "ports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)

    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False, default="tcp")
    state = db.Column(db.String(10), nullable=False, default="open")

    service = db.Column(db.String(40))       # e.g. "ssh", "http", "unknown"
    confidence = db.Column(db.Integer)       # 0-100, strength of the evidence
    product = db.Column(db.String(80))       # e.g. "OpenSSH"
    version = db.Column(db.String(40))       # e.g. "8.9p1"
    banner = db.Column(db.Text)              # raw banner, truncated (evidence)
    method = db.Column(db.String(120))       # how we identified it

    checked_at = db.Column(db.DateTime, nullable=False, default=_utcnow)

    # One port has at most one TLS analysis and one HTTP analysis,
    # and any number of named service checks (Milestone 3+).
    tls_info = db.relationship("TlsInfo", backref="port", uselist=False,
                               cascade="all, delete-orphan")
    http_info = db.relationship("HttpInfo", backref="port", uselist=False,
                                cascade="all, delete-orphan")
    service_checks = db.relationship(
        "ServiceCheck",
        backref=db.backref("port", single_parent=True),
        cascade="all, delete-orphan")
    findings = db.relationship("Finding", backref="port",
                               cascade="all, delete-orphan")


class Finding(db.Model):
    """One vulnerability / hardening finding produced by the rule engine.

    A finding exists ONLY because a rule matched measured observations.
    Rules never invent data: `evidence` holds the facts the rule saw,
    `confidence` says how sure the measurement is, and the explanatory
    fields (description/impact/remediation/references) are fixed text
    written by the rule's author — not generated per scan.
    """
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"), nullable=True)

    rule_id = db.Column(db.String(60), nullable=False)  # e.g. "tls-cert-expired"
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), nullable=False)    # critical/high/medium/low/info
    confidence = db.Column(db.String(15), nullable=False)  # confirmed/likely/potential/informational
    evidence = db.Column(db.Text)        # JSON dict of measured facts
    impact = db.Column(db.Text)          # why it matters
    remediation = db.Column(db.Text)     # how to fix it
    references = db.Column(db.Text)      # JSON list of documentation URLs

    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
