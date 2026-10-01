"""Vulnerability detection rules live here (from Milestone 4).

Each rule will be a small, self-contained module, e.g.:

    rules/ftp_anonymous.py   -> FTP_ANONYMOUS_LOGIN check
    rules/http_headers.py    -> HTTP security-header checks
    rules/tls_version.py     -> obsolete TLS version detection

A rule contains: unique ID, title, severity, the detection logic,
the evidence it collects, and remediation advice — so adding a new
check means adding ONE file, never rewriting the scanner.
"""
