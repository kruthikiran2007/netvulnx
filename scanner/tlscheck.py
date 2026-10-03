# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""TLS/SSL analysis — read-only handshake inspection.

For each port serving TLS we record:
  - negotiated TLS version and cipher suite (and whether the cipher is weak)
  - whether the server still accepts old protocols (TLS 1.0 / 1.1)
  - certificate facts: subject, issuer, SANs, expiry, self-signed?

Everything here is READ-ONLY: we complete TLS handshakes and close.
No application data is ever sent.

Important honesty notes:
  - We do NOT verify the certificate (CERT_NONE) — on purpose. A scanner
    that refused to talk to untrusted certs could never report "this cert
    is expired / self-signed". We inspect; we don't trust.
  - "supports_tls10 = False" means "our handshake with TLS 1.0 failed".
    That is almost always the server refusing, but it can also mean this
    machine's OpenSSL is configured to not offer it. The code says what
    it measured, nothing more.
"""
import socket
import ssl
import tempfile
import os
import warnings
from datetime import datetime, timezone

# Substrings (uppercased) that mark a cipher suite as weak by construction.
_WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5")

# Friendly short names for certificate subject/issuer fields.
_NAME_SHORT = {
    "countryName": "C", "stateOrProvinceName": "ST", "localityName": "L",
    "organizationName": "O", "organizationalUnitName": "OU",
    "commonName": "CN", "emailAddress": "email",
}


def is_weak_cipher(cipher_name: str) -> bool:
    """Deterministic check: is this cipher weak by construction?"""
    upper = (cipher_name or "").upper()
    return any(marker in upper for marker in _WEAK_CIPHER_MARKERS)


def _context(min_version=None, max_version=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect, don't trust (see docstring)
    # Probing TLS 1.0/1.1 is the entire point of _probe_protocol; silence the
    # deprecation warning so scan output stays clean.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if min_version is not None:
            ctx.minimum_version = min_version
        if max_version is not None:
            ctx.maximum_version = max_version
    return ctx


def _decode_der_cert(der: bytes) -> dict:
    """Decode DER certificate bytes into the getpeercert()-style dict.

    Why not just use getpeercert()? With verify_mode=CERT_NONE — which we
    need, so we can INSPECT untrusted/expired/self-signed certs instead of
    refusing to talk to them — CPython returns {} for the dict form of
    getpeercert(). The binary form always works, and _test_decode_cert is
    the standard library's own decoder for it (same output format).
    """
    if not der:
        return {}
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _format_dn(name) -> str:
    """Turn a cert subject/issuer tuple into 'CN=example.com, O=Acme'."""
    parts = []
    for rdn in name or ():
        for key, value in rdn:
            parts.append(f"{_NAME_SHORT.get(key, key)}={value}")
    return ", ".join(parts) or "(empty)"


def _parse_cert_time(value: str):
    """Parse OpenSSL's 'Oct  1 00:00:00 2026 GMT' into an aware datetime."""
    try:
        normalized = " ".join(value.split())
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def _sans(cert: dict) -> list:
    return [value for kind, value in cert.get("subjectAltName", ())
            if kind in ("DNS", "IP Address")]


def hostname_matches(cert: dict, name: str):
    """Does the cert cover `name`? True/False, or None if no identity info."""
    if not name:
        return None
    name_lower = name.lower()
    sans = cert.get("subjectAltName", ())
    if sans:
        for kind, value in sans:
            if kind == "DNS" and _dns_match(value.lower(), name_lower):
                return True
            if kind == "IP Address" and value == name:
                return True
        return False
    # Fallback: Common Name (deprecated practice, but still seen).
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return _dns_match(value.lower(), name_lower)
    return None


def _dns_match(pattern: str, name: str) -> bool:
    if pattern == name:
        return True
    # Wildcard: "*.example.com" matches one level, e.g. "www.example.com".
    if pattern.startswith("*.") and name.count(".") == pattern.count("."):
        return name.endswith(pattern[1:])
    return False


def _probe_protocol(host: str, port: int, version, timeout: float):
    """True if the server completes a handshake offering ONLY this version."""
    try:
        ctx = _context(min_version=version, max_version=version)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock):
                pass  # wrap_socket performs the handshake
        return True
    except Exception:
        return False  # refused, or this client can't offer it (see docstring)


def analyze_tls(host: str, port: int, timeout: float = 5.0,
                server_name: str = None, check_name: str = None,
                light: bool = False) -> dict:
    """Full TLS analysis of one port. Never raises; errors are in the dict.

    server_name: hostname for SNI (only when the target is a hostname).
    check_name:  name/IP to validate against the cert's SANs/CN.
    light:       single handshake only — skips the old-protocol probes.
                 Used by fingerprinting for cheap "is this TLS?" detection;
                 the engine runs the full analysis afterwards.
    """
    result = {"error": None}
    try:
        ctx = _context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
                version = tls.version()            # e.g. "TLSv1.3"
                cipher_name, _, cipher_bits = tls.cipher()
                cert = _decode_der_cert(tls.getpeercert(binary_form=True))
    except Exception as exc:
        result["error"] = f"TLS handshake failed: {type(exc).__name__}: {exc}"
        return result

    not_after = _parse_cert_time(cert.get("notAfter", ""))
    now = datetime.now(timezone.utc)
    subject = _format_dn(cert.get("subject"))
    issuer = _format_dn(cert.get("issuer"))
    name_ok = hostname_matches(cert, check_name) if check_name else None

    result.update({
        "tls_version": version,
        "cipher_name": cipher_name,
        "cipher_bits": cipher_bits,
        "weak_cipher": is_weak_cipher(cipher_name),
        "supports_tls10": None if light else _probe_protocol(host, port, ssl.TLSVersion.TLSv1, timeout),
        "supports_tls11": None if light else _probe_protocol(host, port, ssl.TLSVersion.TLSv1_1, timeout),
        "supports_tls12": None if light else _probe_protocol(host, port, ssl.TLSVersion.TLSv1_2, timeout),
        "cert_subject": subject,
        "cert_issuer": issuer,
        "cert_sans": _sans(cert),
        "cert_not_after": not_after.isoformat() if not_after else None,
        "cert_expired": (not_after < now) if not_after else None,
        "cert_self_signed": bool(subject and subject == issuer),
        "hostname_mismatch": (not name_ok) if name_ok is not None else None,
    })
    return result
