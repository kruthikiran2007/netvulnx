"""Rules over safe service-specific checks (ServiceCheck rows).

These come from the read-only probes in scanner/servicecheck.py:
DNS version.bind, SMTP EHLO/STARTTLS advertisement, FTP anonymous login.
"""
import json

_WSTG_FTP = ("https://owasp.org/www-project-web-security-testing-guide/"
             "stable/4-Web_Application_Security_Testing/"
             "02-Configuration_and_Deployment_Management_Testing/")


def _check(ctx, check_type):
    """The ServiceCheck row for a probe type, or None if it errored."""
    row = (ctx.get("checks") or {}).get(check_type)
    if row is None or getattr(row, "error", None):
        return None
    return row


def _detail(row):
    try:
        return json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return {}


def _match_ftp_anonymous(ctx):
    row = _check(ctx, "ftp_anonymous")
    if row and _detail(row).get("anonymous_allowed") is True:
        d = _detail(row)
        return {"banner": d.get("banner"),
                "user_response": d.get("user_response"),
                "pass_response": d.get("pass_response")}
    return None


def _match_dns_version(ctx):
    row = _check(ctx, "dns_version")
    version = _detail(row).get("version") if row else None
    if version:
        return {"version": version}
    return None


def _match_smtp_no_starttls(ctx):
    row = _check(ctx, "smtp_ehlo")
    if row and _detail(row).get("starttls_advertised") is False:
        d = _detail(row)
        return {"banner": d.get("banner"),
                "extensions": d.get("extensions")}
    return None


RULES = [
    {
        "id": "ftp-anonymous-allowed",
        "title": "FTP allows anonymous login",
        "severity": "medium",
        "confidence": "confirmed",
        "description": (
            "The FTP server accepted an anonymous login (username "
            "'anonymous'). We logged in and immediately quit — nothing was "
            "listed or downloaded."),
        "impact": (
            "Anonymous FTP often exposes files that were never meant to be "
            "public, and it is a classic foothold: attackers upload or "
            "download material and probe the server further from inside."),
        "remediation": (
            "Disable anonymous access unless the server is a deliberate "
            "public file drop. If it must stay, audit exactly which "
            "directories are exposed and make them read-only."),
        "references": [_WSTG_FTP],
        "match": _match_ftp_anonymous,
    },
    {
        "id": "dns-version-disclosure",
        "title": "DNS server discloses its version",
        "severity": "low",
        "confidence": "confirmed",
        "description": (
            "The DNS server answered a version.bind query with its software "
            "version. This is a standard informational query — not an attack."),
        "impact": (
            "Version strings let attackers target known vulnerabilities of "
            "that exact release. Minor, but free intelligence for them."),
        "remediation": (
            "Configure the DNS server to return a generic or empty version "
            "string (e.g. BIND's 'version \"none\";')."),
        "references": [_WSTG_FTP],
        "match": _match_dns_version,
    },
    {
        "id": "smtp-starttls-missing",
        "title": "SMTP server does not advertise STARTTLS",
        "severity": "low",
        "confidence": "confirmed",
        "description": (
            "The SMTP server's EHLO response did not advertise STARTTLS, so "
            "clients cannot upgrade the connection to encrypted mail "
            "delivery."),
        "impact": (
            "Mail relayed through this server may travel in cleartext, "
            "readable by anyone on the network path."),
        "remediation": (
            "Enable and advertise STARTTLS on the mail server and obtain a "
            "valid certificate for it."),
        "references": [_WSTG_FTP],
        "match": _match_smtp_no_starttls,
    },
]
