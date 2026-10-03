# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Rules over TLS observations (TlsInfo rows from scanner/tlscheck.py).

Every rule here fires only on a directly measured fact: we completed the
handshake ourselves, so there is no guessing.
"""
from datetime import datetime, timezone

_MOZ_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS"
_RFC8996 = "https://www.rfc-editor.org/rfc/rfc8996.html"
_OWASP_TLSP = ("https://cheatsheetseries.owasp.org/cheatsheets/"
              "Transport_Layer_Protection_Cheat_Sheet.html")


def _tls(ctx):
    """The TlsInfo observation, or None if we have no usable TLS data."""
    tls = ctx.get("tls")
    if tls is None or getattr(tls, "error", None):
        return None
    return tls


def _match_expired(ctx):
    tls = _tls(ctx)
    if tls and tls.cert_expired:
        days = None
        not_after = tls.cert_not_after
        if isinstance(not_after, str):  # tolerate ISO strings, not just datetimes
            try:
                not_after = datetime.fromisoformat(not_after)
            except ValueError:
                not_after = None
        if not_after and not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        if not_after:
            days = (datetime.now(timezone.utc) - not_after).days
        return {"subject": tls.cert_subject,
                "not_after": str(tls.cert_not_after),
                "days_expired": days}
    return None


def _match_self_signed(ctx):
    tls = _tls(ctx)
    if tls and tls.cert_self_signed:
        return {"subject": tls.cert_subject, "issuer": tls.cert_issuer}
    return None


def _match_hostname_mismatch(ctx):
    tls = _tls(ctx)
    if tls and tls.hostname_mismatch:
        return {"subject": tls.cert_subject,
                "sans": tls.cert_sans,
                "target": ctx.get("target")}
    return None


def _match_obsolete_protocol(ctx):
    tls = _tls(ctx)
    if not tls:
        return None
    accepted = [v for v, ok in (("TLS 1.0", tls.supports_tls10),
                                ("TLS 1.1", tls.supports_tls11)) if ok]
    if accepted:
        return {"accepted": ", ".join(accepted),
                "negotiated": tls.tls_version}
    return None


def _match_weak_cipher(ctx):
    tls = _tls(ctx)
    if tls and tls.weak_cipher:
        return {"cipher": tls.cipher_name, "bits": tls.cipher_bits}
    return None


RULES = [
    {
        "id": "tls-cert-expired",
        "title": "TLS certificate has expired",
        "severity": "high",
        "confidence": "confirmed",
        "description": (
            "The server presented a TLS certificate that is past its validity "
            "period. Clients will show security warnings, and the cryptographic "
            "identity of the server can no longer be trusted."),
        "impact": (
            "Users see browser warnings and may be trained to click through "
            "them — which also trains them to ignore warnings for real "
            "attacks. Automated clients and APIs typically refuse to connect "
            "at all, causing outages."),
        "remediation": (
            "Renew the certificate from your certificate authority and install "
            "it on the server. Put the expiry date in monitoring so renewal "
            "happens before — not after — it lapses."),
        "references": [_OWASP_TLSP],
        "match": _match_expired,
    },
    {
        "id": "tls-cert-self-signed",
        "title": "TLS certificate is self-signed",
        "severity": "medium",
        "confidence": "confirmed",
        "description": (
            "The server's certificate was issued by itself, not by a trusted "
            "certificate authority. There is no independent proof of who "
            "operates this server."),
        "impact": (
            "Clients cannot distinguish this server from an impostor, which "
            "makes man-in-the-middle attacks easier. Browsers show warnings "
            "that teach users to click through security alerts."),
        "remediation": (
            "Obtain a certificate from a trusted certificate authority "
            "(many are free). Self-signed certificates are acceptable only "
            "for internal test environments where clients explicitly trust them."),
        "references": [_OWASP_TLSP],
        "match": _match_self_signed,
    },
    {
        "id": "tls-cert-hostname-mismatch",
        "title": "TLS certificate does not cover this host",
        "severity": "medium",
        "confidence": "confirmed",
        "description": (
            "The certificate's Subject Alternative Names do not include the "
            "host we connected to. The certificate may belong to a different "
            "server, or the service may be misconfigured."),
        "impact": (
            "Clients will refuse the connection or warn the user. A mismatched "
            "certificate is also what an attacker intercepting traffic would "
            "present, so warnings get normalized."),
        "remediation": (
            "Issue a certificate that lists this host's DNS name (or IP) in "
            "its Subject Alternative Names, or point the service at the "
            "correct certificate."),
        "references": [_OWASP_TLSP],
        "match": _match_hostname_mismatch,
    },
    {
        "id": "tls-obsolete-protocol",
        "title": "Server accepts obsolete TLS 1.0 / 1.1",
        "severity": "high",
        "confidence": "confirmed",
        "description": (
            "The server completed a handshake using TLS 1.0 or TLS 1.1, "
            "protocols formally deprecated by RFC 8996. We verified this with "
            "a real handshake, not a version guess."),
        "impact": (
            "TLS 1.0/1.1 have known weaknesses (e.g. BEAST, weak cipher "
            "negotiation). Attackers can try to force connections down to the "
            "weakest protocol the server accepts."),
        "remediation": (
            "Disable TLS 1.0 and 1.1 on the server; support TLS 1.2 as a "
            "minimum (TLS 1.3 preferred). See Mozilla's Server Side TLS guide "
            "for safe configuration profiles."),
        "references": [_RFC8996, _MOZ_TLS],
        "match": _match_obsolete_protocol,
    },
    {
        "id": "tls-weak-cipher",
        "title": "Server negotiated a weak cipher suite",
        "severity": "medium",
        "confidence": "confirmed",
        "description": (
            "The handshake settled on a cipher suite that is weak by "
            "construction (e.g. RC4, single DES, 3DES, export-grade, or "
            "unauthenticated ciphers)."),
        "impact": (
            "Weak ciphers can allow an attacker who captures traffic to "
            "decrypt it — sometimes in real time (RC4), sometimes with "
            "moderate effort (3DES/SWEET32)."),
        "remediation": (
            "Restrict the server to strong cipher suites "
            "(AES-GCM or ChaCha20-Poly1305 with ECDHE key exchange) and "
            "re-test. Mozilla's Server Side TLS guide lists safe suites."),
        "references": [_MOZ_TLS],
        "match": _match_weak_cipher,
    },
]
