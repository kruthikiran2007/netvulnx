"""Rules over HTTP observations (HttpInfo rows from scanner/httpcheck.py).

All of these fire on response headers / bodies we actually received.
Missing-header rules are hardening notes, not emergencies — their severity
reflects that.
"""
import json
import re

_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_OWASP_CLICKJACK = "https://owasp.org/www-community/attacks/Clickjacking"

_VERSION_RE = re.compile(r"/\d+(\.\d+)+")


def _http(ctx):
    http = ctx.get("http")
    if http is None or getattr(http, "error", None):
        return None
    return http


def _missing_headers(http):
    try:
        return set(json.loads(http.missing_security_headers or "[]"))
    except (ValueError, TypeError):
        return set()


def _match_hsts(ctx):
    http = _http(ctx)
    if http and http.scheme == "https" and "HSTS" in _missing_headers(http):
        return {"final_url": http.final_url}
    return None


def _match_csp(ctx):
    http = _http(ctx)
    if http and "CSP" in _missing_headers(http):
        return {"final_url": http.final_url}
    return None


def _match_clickjacking(ctx):
    http = _http(ctx)
    if http and "X-Frame-Options" in _missing_headers(http):
        return {"final_url": http.final_url}
    return None


def _match_directory_listing(ctx):
    http = _http(ctx)
    if http and http.directory_listing:
        return {"final_url": http.final_url, "page_title": http.page_title}
    return None


def _match_default_page(ctx):
    http = _http(ctx)
    if http and http.default_page:
        return {"final_url": http.final_url, "page_title": http.page_title}
    return None


def _match_version_disclosure(ctx):
    http = _http(ctx)
    if http and http.server_header and _VERSION_RE.search(http.server_header):
        return {"server_header": http.server_header,
                "x_powered_by": getattr(http, "powered_by", None),
                "final_url": http.final_url}
    return None


def _match_no_https_redirect(ctx):
    http = _http(ctx)
    if http and http.scheme == "http" and not http.redirects_to_https:
        return {"final_url": http.final_url}
    return None


RULES = [
    {
        "id": "http-hsts-missing",
        "title": "HSTS not enabled on HTTPS service",
        "severity": "medium",
        "confidence": "confirmed",
        "description": (
            "The HTTPS response does not include a Strict-Transport-Security "
            "header. HSTS tells browsers to always use HTTPS for this host, "
            "closing the window for SSL-stripping downgrade attacks."),
        "impact": (
            "On hostile networks an attacker can try to downgrade visitors to "
            "plain HTTP on their first visit and intercept credentials or "
            "session cookies."),
        "remediation": (
            "Send 'Strict-Transport-Security: max-age=31536000' (and later "
            "'includeSubDomains') on all HTTPS responses."),
        "references": [_OWASP_HEADERS],
        "match": _match_hsts,
    },
    {
        "id": "http-csp-missing",
        "title": "Content-Security-Policy not set",
        "severity": "low",
        "confidence": "confirmed",
        "description": (
            "The response has no Content-Security-Policy header, so the "
            "browser applies no restrictions on where scripts, styles and "
            "other resources may load from."),
        "impact": (
            "Without CSP, a cross-site scripting flaw is much easier to "
            "exploit — injected scripts run with no policy to stop them."),
        "remediation": (
            "Define a Content-Security-Policy that whitelists only the "
            "resource origins the application needs. Start in report-only "
            "mode, then enforce."),
        "references": [_OWASP_HEADERS],
        "match": _match_csp,
    },
    {
        "id": "http-clickjacking-protection-missing",
        "title": "No clickjacking protection header",
        "severity": "low",
        "confidence": "confirmed",
        "description": (
            "The response sets neither X-Frame-Options nor a CSP "
            "frame-ancestors directive, so the page can be embedded in an "
            "invisible frame on another site."),
        "impact": (
            "Attackers can layer invisible frames over decoy content to trick "
            "users into clicking buttons or links they cannot see "
            "(clickjacking)."),
        "remediation": (
            "Send 'X-Frame-Options: DENY' (or SAMEORIGIN where framing is "
            "needed), or use CSP 'frame-ancestors' — the modern replacement."),
        "references": [_OWASP_HEADERS, _OWASP_CLICKJACK],
        "match": _match_clickjacking,
    },
    {
        "id": "http-directory-listing",
        "title": "Directory listing enabled",
        "severity": "medium",
        "confidence": "confirmed",
        "description": (
            "The web server returned an auto-generated listing of a "
            "directory's contents. We fetched it with a normal GET request — "
            "no tricks involved."),
        "impact": (
            "Listings expose file names (backups, config fragments, old "
            "versions) that help an attacker map the application and pick "
            "targets."),
        "remediation": (
            "Disable directory indexing in the server configuration and make "
            "sure every directory either has an index file or returns 403."),
        "references": [_OWASP_HEADERS],
        "match": _match_directory_listing,
    },
    {
        "id": "http-default-page",
        "title": "Default / unconfigured web page",
        "severity": "info",
        "confidence": "likely",
        "description": (
            "The site shows a stock welcome page from the web server or "
            "framework, which suggests the installation was never customized "
            "or hardened. Confidence is 'likely' because some sites keep a "
            "default-looking page deliberately."),
        "impact": (
            "On its own this is harmless, but uncustomized installs often "
            "keep default settings elsewhere too — it is a smell worth "
            "checking."),
        "remediation": (
            "Replace the default page with real content (or remove the site) "
            "and review the server's default configuration."),
        "references": [_OWASP_HEADERS],
        "match": _match_default_page,
    },
    {
        "id": "http-server-version-disclosure",
        "title": "Server header discloses software version",
        "severity": "info",
        "confidence": "confirmed",
        "description": (
            "The Server response header names the software and its version. "
            "This is factual information from the banner — it is not a "
            "vulnerability by itself."),
        "impact": (
            "Version details let an attacker look up known vulnerabilities for "
            "exactly this release instead of probing blindly."),
        "remediation": (
            "Configure the server to send a minimal Server header (or none). "
            "Treat this as hygiene — patching matters far more than hiding "
            "the version."),
        "references": [_OWASP_HEADERS],
        "match": _match_version_disclosure,
    },
    {
        "id": "http-no-https-redirect",
        "title": "HTTP service does not redirect to HTTPS",
        "severity": "info",
        "confidence": "confirmed",
        "description": (
            "The plain-HTTP service answered without redirecting to HTTPS. "
            "Informational: many sites keep HTTP for compatibility, but any "
            "sensitive traffic should prefer HTTPS."),
        "impact": (
            "Users or clients that use the HTTP URL send traffic unencrypted, "
            "exposing it to interception on the network path."),
        "remediation": (
            "If the service handles anything sensitive, redirect all HTTP "
            "requests to the HTTPS equivalent (301) and enable HSTS there."),
        "references": [_OWASP_HEADERS],
        "match": _match_no_https_redirect,
    },
]
