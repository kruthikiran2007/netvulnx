# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Rules over the database greeting checks (Milestone 21).

The checks (scanner/dbcheck.py) never authenticate:

  mysql-eol-version            (high/medium/low by version)
      - the server's own handshake advertises its version; releases
        past end-of-life get flagged with per-version severity.
  postgres-ssl-not-supported   (medium)
      - the server answered 'N' to SSLRequest: clients cannot use TLS,
        so credentials and queries travel in cleartext.
  redis-no-auth                (high)
      - the server answered PING without authentication: anyone on the
        network can read and write its data.
"""
import json

from scanner.dbcheck import parse_mysql_version

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _check(ctx, check_type):
    row = (ctx.get("checks") or {}).get(check_type)
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    if d.get("error"):
        return None
    return d


# --------------------------------------------------------------------------
# MySQL / MariaDB end-of-life versions (as of late 2026)
# --------------------------------------------------------------------------
def _mysql_severity(flavor, major, minor):
    """(severity, reason) or None when the version is still supported."""
    if major is None:
        return None
    if flavor == "mariadb":
        if major < 10 or (major == 10 and minor < 6):
            return ("high", "MariaDB 10.5 and older reached end-of-life "
                             "(10.5 EOL June 2025)")
        if major == 10 and minor < 11:
            return ("medium", "MariaDB 10.6 reached end-of-life July 2026; "
                               "10.11+ is the supported LTS line")
        return None
    # Oracle MySQL
    if major < 8:
        return ("high", "MySQL 5.7 and older reached end-of-life "
                         "October 2023 — no security patches")
    if major == 8 and minor == 0:
        return ("medium", "MySQL 8.0 reached end-of-life April 2026")
    return None


def _match_mysql_eol(ctx):
    d = _check(ctx, "mysql_greeting")
    if not d or not d.get("server_version"):
        return None
    flavor, major, minor = parse_mysql_version(d["server_version"])
    sev = _mysql_severity(flavor, major, minor)
    if not sev:
        return None
    severity, reason = sev
    return {
        "server_version": d["server_version"],
        "_finding": {
            "title": f"{'MariaDB' if flavor == 'mariadb' else 'MySQL'} "
                     f"{d['server_version']} is past end-of-life",
            "severity": severity,
            "description": (f"The database handshake advertises version "
                            f"{d['server_version']}. {reason}."),
            "impact": ("Unpatched vulnerabilities in the database engine stay "
                       "exploitable; vendors publish no fixes for EOL lines."),
            "remediation": ("Upgrade to a supported release "
                            "(MySQL 8.4 LTS / 9.x, or MariaDB 10.11+/11.4 LTS) "
                            "and re-run the scan to confirm the new version."),
        },
    }


# --------------------------------------------------------------------------
# PostgreSQL without TLS
# --------------------------------------------------------------------------
def _match_postgres_no_ssl(ctx):
    d = _check(ctx, "postgres_ssl")
    if not d or d.get("ssl_supported") is not False:
        return None
    return {
        "evidence": "server answered 'N' to SSLRequest",
        "_finding": {
            "title": "PostgreSQL does not offer TLS",
            "severity": "medium",
            "description": ("The server answered 'N' to the standard "
                            "SSLRequest probe: clients cannot negotiate TLS, "
                            "so usernames, passwords and query data travel "
                            "in cleartext on the network."),
            "impact": ("Passive network observers (and anyone able to "
                       "intercept traffic) can capture database credentials "
                       "and data."),
            "remediation": ("Enable ssl=on in postgresql.conf with a valid "
                            "server certificate, set hostssl entries in "
                            "pg_hba.conf, and restart PostgreSQL."),
        },
    }


# --------------------------------------------------------------------------
# Redis without authentication
# --------------------------------------------------------------------------
def _match_redis_no_auth(ctx):
    d = _check(ctx, "redis_ping")
    if not d or d.get("auth_required") is not False:
        return None
    return {
        "evidence": "server answered '+PONG' to unauthenticated PING",
        "_finding": {
            "title": "Redis accepts commands without authentication",
            "severity": "high",
            "description": ("The server answered our PING with +PONG and no "
                            "password was required. Anyone who can reach "
                            "this port can read, write and delete data, and "
                            "abuse Redis commands for further access."),
            "impact": ("Full data compromise and a well-known stepping "
                       "stone for remote code execution on the host."),
            "remediation": ("Set 'requirepass' with a strong password in "
                            "redis.conf (or use ACLs), bind Redis to "
                            "localhost / a private interface, and firewall "
                            "port 6379."),
        },
    }


RULES = [
    {
        "id": "mysql-eol-version",
        "title": "Database version past end-of-life",  # refined per finding
        "severity": "medium",  # fallback; refined per finding
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://endoflife.date/mysql",
                       "https://endoflife.date/mariadb"],
        "match": _match_mysql_eol,
    },
    {
        "id": "postgres-ssl-not-supported",
        "title": "PostgreSQL does not offer TLS",
        "severity": "medium",
        "confidence": "confirmed",
        "description": ("The server answered 'N' to the standard SSLRequest "
                        "probe: clients cannot negotiate TLS."),
        "impact": ("Network observers can capture database credentials and "
                   "query data in cleartext."),
        "remediation": ("Enable ssl=on in postgresql.conf with a valid "
                        "certificate, use hostssl in pg_hba.conf, restart."),
        "references": ["https://www.postgresql.org/docs/current/ssl-tcp.html"],
        "match": _match_postgres_no_ssl,
    },
    {
        "id": "redis-no-auth",
        "title": "Redis accepts commands without authentication",
        "severity": "high",
        "confidence": "confirmed",
        "description": ("The server answered PING with +PONG and no password "
                        "was required."),
        "impact": ("Full data compromise; a known stepping stone for remote "
                   "code execution."),
        "remediation": ("Set 'requirepass' / ACLs in redis.conf, bind to "
                        "localhost, firewall port 6379."),
        "references": ["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"],
        "match": _match_redis_no_auth,
    },
]
