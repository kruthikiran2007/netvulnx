"""Unit tests for the rule engine (Milestone 4).

We test rule LOGIC with synthetic observation objects — that is legitimate
unit testing of the matcher functions, not fabricated scan output. Each
rule is checked for:
  - fires when its condition holds (with real evidence values), and
  - stays silent when the condition doesn't hold (no false positives), and
  - stays silent when the observation is missing/errored (no crashes).

Conventions: SimpleNamespace objects stand in for TlsInfo / HttpInfo /
ServiceCheck rows; the `checks` dict maps check_type -> row.
"""
import json
from datetime import datetime
from types import SimpleNamespace

import rules
from rules import tls_rules, http_rules, service_rules
from rules.scoring import score_findings, SEVERITY_WEIGHTS


def _ctx(tls=None, http=None, checks=None, target="127.0.0.1"):
    return {"target": target, "tls": tls, "http": http,
            "checks": checks or {}}


def _tls(**kw):
    base = dict(error=None, cert_expired=False, cert_self_signed=False,
                hostname_mismatch=False, supports_tls10=False,
                supports_tls11=False, weak_cipher=False,
                cert_subject="CN=test", cert_issuer="CN=test",
                cert_not_after=None, cert_sans="", tls_version="TLSv1.3",
                cipher_name="AES", cipher_bits=256)
    base.update(kw)
    return SimpleNamespace(**base)


def _http(**kw):
    base = dict(error=None, scheme="https", final_url="https://x/",
                server_header=None, powered_by=None,
                missing_security_headers="[]", redirects_to_https=False,
                page_title=None, directory_listing=False, default_page=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _check(check_type, summary, detail, error=None):
    # NOTE: attribute names here must match app/models.py exactly —
    # test doubles with wrong names give false confidence (real bug, M4).
    return SimpleNamespace(check_type=check_type, summary=summary,
                           details=json.dumps(detail), error=error)


def _rule(rule_id):
    return next(r for r in rules.ALL_RULES if r["id"] == rule_id)


def _fires(rule_id, ctx):
    rule = _rule(rule_id)
    ev = rule["match"](ctx)
    assert ev, f"{rule_id} should have matched"
    return rule, ev


def _silent(rule_id, ctx):
    rule = _rule(rule_id)
    assert rule["match"](ctx) is None, f"{rule_id} should NOT have matched"


# ---------- registry ----------

def test_registry_unique_ids_and_schema():
    ids = [r["id"] for r in rules.ALL_RULES]
    assert len(ids) == len(set(ids)) and len(ids) >= 10
    for r in rules.ALL_RULES:
        assert r["severity"] in rules.SEVERITIES
        assert r["confidence"] in rules.CONFIDENCES
        assert r["references"]  # every rule documents its sources


def test_evaluate_skips_broken_rule():
    bad = {"id": "x", "title": "x", "severity": "low",
           "confidence": "confirmed", "description": "x", "impact": "x",
           "remediation": "x", "references": ["https://example.com"],
           "match": lambda ctx: 1 / 0}
    real = rules.ALL_RULES
    rules.ALL_RULES = [bad]
    try:
        assert rules.evaluate({}) == []  # must not raise
    finally:
        rules.ALL_RULES = real


# ---------- TLS rules ----------

def test_tls_cert_expired():
    rule, ev = _fires("tls-cert-expired",
                      _ctx(tls=_tls(cert_expired=True,
                                    cert_not_after="2020-01-01")))
    assert rule["severity"] == "high" and rule["confidence"] == "confirmed"
    assert "subject" in ev

    _silent("tls-cert-expired", _ctx(tls=_tls(cert_expired=False)))
    _silent("tls-cert-expired", _ctx(tls=None))                    # no TLS data
    _silent("tls-cert-expired", _ctx(tls=_tls(error="boom")))      # errored


def test_tls_cert_self_signed():
    rule, ev = _fires("tls-cert-self-signed",
                      _ctx(tls=_tls(cert_self_signed=True)))
    assert rule["severity"] == "medium"
    assert ev["subject"] == ev["issuer"]
    _silent("tls-cert-self-signed", _ctx(tls=_tls(cert_self_signed=False)))


def test_tls_hostname_mismatch():
    _, ev = _fires("tls-cert-hostname-mismatch",
                   _ctx(tls=_tls(hostname_mismatch=True), target="10.0.0.5"))
    assert ev["target"] == "10.0.0.5"
    _silent("tls-cert-hostname-mismatch", _ctx(tls=_tls(hostname_mismatch=False)))


def test_tls_obsolete_protocol():
    rule, ev = _fires("tls-obsolete-protocol",
                      _ctx(tls=_tls(supports_tls10=True)))
    assert rule["severity"] == "high"
    assert "TLS 1.0" in ev["accepted"]
    _fires("tls-obsolete-protocol", _ctx(tls=_tls(supports_tls11=True)))
    # Modern-only server: silent
    _silent("tls-obsolete-protocol",
            _ctx(tls=_tls(supports_tls10=False, supports_tls11=False)))


def test_tls_weak_cipher():
    _, ev = _fires("tls-weak-cipher",
                   _ctx(tls=_tls(weak_cipher=True, cipher_name="RC4",
                                 cipher_bits=128)))
    assert ev["cipher"] == "RC4"
    _silent("tls-weak-cipher", _ctx(tls=_tls(weak_cipher=False)))


# ---------- HTTP rules ----------

def test_http_hsts_missing_only_on_https():
    _fires("http-hsts-missing",
           _ctx(http=_http(scheme="https",
                           missing_security_headers='["HSTS", "CSP"]')))
    # Plain HTTP can't have HSTS enforced the same way: silent
    _silent("http-hsts-missing",
            _ctx(http=_http(scheme="http",
                            missing_security_headers='["HSTS"]')))
    # HSTS present: silent
    _silent("http-hsts-missing",
            _ctx(http=_http(scheme="https", missing_security_headers="[]")))


def test_http_csp_and_clickjacking():
    _fires("http-csp-missing",
           _ctx(http=_http(missing_security_headers='["CSP"]')))
    _fires("http-clickjacking-protection-missing",
           _ctx(http=_http(missing_security_headers='["X-Frame-Options"]')))
    _silent("http-csp-missing", _ctx(http=_http(missing_security_headers="[]")))


def test_http_directory_listing():
    rule, ev = _fires("http-directory-listing",
                      _ctx(http=_http(directory_listing=True,
                                      final_url="http://x/files/")))
    assert rule["severity"] == "medium" and rule["confidence"] == "confirmed"
    _silent("http-directory-listing", _ctx(http=_http(directory_listing=False)))


def test_http_default_page_is_likely_not_confirmed():
    rule, _ = _fires("http-default-page",
                     _ctx(http=_http(default_page="nginx default page")))
    assert rule["confidence"] == "likely"  # honest uncertainty
    assert rule["severity"] == "info"
    _silent("http-default-page", _ctx(http=_http(default_page=None)))


def test_http_version_disclosure_needs_version_pattern():
    _, ev = _fires("http-server-version-disclosure",
                   _ctx(http=_http(server_header="Apache/2.4.1",
                                   powered_by="PHP/8.1.2")))
    assert ev["server_header"] == "Apache/2.4.1"
    assert ev["x_powered_by"] == "PHP/8.1.2"
    _silent("http-server-version-disclosure",
            _ctx(http=_http(server_header="Apache")))   # no version: silent
    _silent("http-server-version-disclosure",
            _ctx(http=_http(server_header=None)))


def test_http_no_https_redirect():
    _fires("http-no-https-redirect",
           _ctx(http=_http(scheme="http", redirects_to_https=False)))
    _silent("http-no-https-redirect",
            _ctx(http=_http(scheme="http", redirects_to_https=True)))
    _silent("http-no-https-redirect",
            _ctx(http=_http(scheme="https", redirects_to_https=False)))


# ---------- service rules ----------

def test_ftp_anonymous():
    row = _check("ftp_anonymous", "ANONYMOUS LOGIN ALLOWED",
                 {"banner": "220 FTP", "user_response": "331",
                  "pass_response": "230", "anonymous_allowed": True})
    rule, ev = _fires("ftp-anonymous-allowed",
                      _ctx(checks={"ftp_anonymous": row}))
    assert rule["confidence"] == "confirmed"
    assert ev["pass_response"] == "230"
    # Refused login: silent
    row2 = _check("ftp_anonymous", "anonymous login denied (code 530)",
                  {"user_response": "530", "anonymous_allowed": False})
    _silent("ftp-anonymous-allowed", _ctx(checks={"ftp_anonymous": row2}))


def test_dns_version_disclosure():
    row = _check("dns_version", "DISCLOSED", {"version": "BIND 9.16"})
    _, ev = _fires("dns-version-disclosure", _ctx(checks={"dns_version": row}))
    assert ev["version"] == "BIND 9.16"
    row2 = _check("dns_version", "REFUSED", {})
    _silent("dns-version-disclosure", _ctx(checks={"dns_version": row2}))


def test_smtp_no_starttls():
    row = _check("smtp_ehlo", "250 OK",
                 {"banner": "220 mail", "starttls_advertised": False,
                  "extensions": ["PIPELINING"]})
    _fires("smtp-starttls-missing", _ctx(checks={"smtp_ehlo": row}))
    row2 = _check("smtp_ehlo", "250 OK",
                  {"banner": "220 mail", "starttls_advertised": True})
    _silent("smtp-starttls-missing", _ctx(checks={"smtp_ehlo": row2}))


# ---------- scoring ----------

def test_scoring_weights():
    f = [SimpleNamespace(severity="critical"), SimpleNamespace(severity="high"),
         SimpleNamespace(severity="medium"), SimpleNamespace(severity="low"),
         SimpleNamespace(severity="info")]
    assert score_findings(f) == 10 + 5 + 3 + 1 + 0
    assert SEVERITY_WEIGHTS["info"] == 0  # info never moves the score


def test_open_port_alone_produces_no_findings():
    """The standing rule: an open port is not a vulnerability."""
    port = SimpleNamespace(port=22, service="ssh")
    ctx = _ctx()  # no observations at all
    ctx["port"] = port
    assert rules.evaluate(ctx) == []


def test_rules_against_real_model_attributes():
    """Regression test: run the rules against REAL (unpersisted) SQLAlchemy
    model instances, not test doubles. evaluate() swallows per-rule
    exceptions, so a rule touching a renamed/missing column would silently
    never fire — this test catches that by demanding every applicable rule
    matches an all-positive fixture."""
    from app.models import TlsInfo, HttpInfo, ServiceCheck

    tls = TlsInfo(
        cert_expired=True, cert_subject="CN=x",
        cert_not_after=datetime(2020, 1, 1), cert_self_signed=True,
        hostname_mismatch=True, supports_tls10=True, weak_cipher=True,
        cipher_name="RC4", cipher_bits=40, tls_version="TLSv1")
    http = HttpInfo(
        scheme="https", final_url="https://x/",
        server_header="Apache/2.4.1", powered_by="PHP/8.0",
        missing_security_headers='["HSTS", "CSP", "X-Frame-Options"]',
        redirects_to_https=False, directory_listing=True,
        default_page="nginx default page", page_title="Index of /")
    checks = {
        "ftp_anonymous": ServiceCheck(
            check_type="ftp_anonymous", summary="ANONYMOUS LOGIN ALLOWED",
            details=json.dumps({"anonymous_allowed": True, "banner": "220 x",
                                "user_response": "331", "pass_response": "230"})),
        "dns_version": ServiceCheck(
            check_type="dns_version", summary="version disclosed",
            details=json.dumps({"version": "BIND 9.16"})),
        "smtp_ehlo": ServiceCheck(
            check_type="smtp_ehlo", summary="no STARTTLS advertised",
            details=json.dumps({"starttls_advertised": False,
                                "banner": "220 x", "extensions": []})),
    }
    ctx = {"tls": tls, "http": http, "checks": checks, "target": "127.0.0.1"}
    matched = {r["id"] for r, _ in rules.evaluate(ctx)}
    # http-no-https-redirect is https-only by design; everything else fires.
    expected = {r["id"] for r in rules.ALL_RULES} - {"http-no-https-redirect"}
    assert matched == expected, f"missing: {expected - matched}"
