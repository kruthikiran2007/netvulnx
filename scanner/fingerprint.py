"""Service fingerprinting: WHAT is listening on an open port, and how sure are we?

A port number alone is only a hint — anyone can run HTTP on port 22.
So we identify services from actual protocol behavior:

  1. PASSIVE banner grab: connect and listen. Many services greet you
     immediately (SSH, FTP, SMTP, Telnet).
  2. ACTIVE probe: if nothing greeted us, send a minimal, benign HTTP
     request. A web server will answer; anything else will hang up or
     send garbage — both are informative.
  2b. TLS handshake attempt: a TLS service answers neither of the above
     with plaintext, so try one real (read-only) TLS handshake.
  3. PORT HINT: if all else fails, guess from the well-known port number —
     clearly labeled as unverified.

Every result carries a CONFIDENCE score (0-100) that reflects the strength
of the evidence, never a guess dressed up as a fact:

    90-99  banner matched the protocol's grammar (e.g. "SSH-2.0-...")
    75-89  parsed an actual protocol response (e.g. HTTP + Server header)
    40-60  port-number hint only — explicitly unverified
    10-25  unknown: something answered, but we can't identify it

All reads are small (<=4KB), time-boxed, and read-only. We never log in,
never brute-force, never exploit.
"""
import re
import socket

from scanner import tlscheck

BANNER_MAX = 500  # store at most this many banner characters


# --------------------------------------------------------------------------
# Low-level network helpers
# --------------------------------------------------------------------------

def _recv_all(sock: socket.socket, timeout: float, limit: int = 4096) -> bytes:
    """Read whatever the server sends, until timeout or limit. Never raises."""
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(min(1024, limit - len(data)))
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    return data


def _grab_banner(ip: str, port: int, timeout: float) -> bytes:
    """Connect and listen passively — many services greet immediately."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            return _recv_all(sock, timeout)
    except OSError:
        return b""


def _http_probe(ip: str, port: int, timeout: float) -> bytes:
    """Send a minimal benign HTTP request and read the response."""
    request = (f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: NetVulnX/1.0\r\n\r\n").encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(request)
            return _recv_all(sock, timeout)
    except OSError:
        return b""


# --------------------------------------------------------------------------
# Banner / response parsers — each returns a dict or None
# --------------------------------------------------------------------------

def _parse_ssh(banner: str):
    # Real SSH servers greet like:  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    m = re.match(r"SSH-(\d\.\d)-([^\r\n]+)", banner)
    if not m:
        return None
    product_raw = m.group(2).strip()
    # Split "OpenSSH_8.9p1" or "dropbear_2022.83" into product + version.
    pm = re.match(r"([A-Za-z][\w.\-]*?)[_\- ](\d[\w.\-]*)", product_raw)
    product, version = (pm.group(1), pm.group(2)) if pm else (product_raw, None)
    return {"service": "ssh", "product": product, "version": version,
            "confidence": 96, "method": "SSH banner matched protocol grammar"}


def _parse_ftp(banner: str):
    # FTP servers greet like:  220 (vsFTPd 3.0.3)
    # NOTE: SMTP servers also greet with 220 — if the banner carries SMTP
    # markers, this is NOT ftp; let the SMTP parser claim it.
    if not re.match(r"220[ -]", banner):
        return None
    if re.search(r"smtp|esmtp|postfix|sendmail|exim", banner, re.I):
        return None
    product, version = None, None
    for name in ("vsftpd", "ProFTPD", "FileZilla", "Pure-FTPd", "Microsoft FTP"):
        if name.lower() in banner.lower():
            product = name
            vm = re.search(r"(\d+\.\d+[\.\d]*)", banner)
            version = vm.group(1) if vm else None
            break
    return {"service": "ftp", "product": product, "version": version,
            "confidence": 92, "method": "FTP 220 greeting matched"}


def _parse_smtp(banner: str):
    # SMTP servers greet like:  220 mail.example.com ESMTP Postfix
    if not re.match(r"220[ -]", banner):
        return None
    if not re.search(r"smtp|esmtp|postfix|sendmail|exim", banner, re.I):
        return None
    product = next((n for n in ("Postfix", "Sendmail", "Exim", "Microsoft ESMTP")
                    if n.lower() in banner.lower()), None)
    vm = re.search(r"(\d+\.\d+[\.\d]*)", banner)
    return {"service": "smtp", "product": product,
            "version": vm.group(1) if vm else None,
            "confidence": 90, "method": "SMTP 220 greeting matched"}


def _parse_http_response(text: str):
    # Matches both a passively-grabbed banner and our active HEAD response.
    m = re.search(r"^(HTTP/\d(?:\.\d)?)\s+(\d{3})", text, re.M)
    if not m:
        return None
    server_m = re.search(r"^Server:\s*([^\r\n]+)", text, re.M | re.I)
    server = server_m.group(1).strip() if server_m else None
    product, version = None, None
    if server:
        vm = re.match(r"([^\s/]+)(?:/(\S+))?", server)
        if vm:
            product, version = vm.group(1), vm.group(2)
    return {"service": "http", "product": product, "version": version,
            "confidence": 88 if server else 80,
            "method": "HTTP response parsed" + (" (Server header)" if server else "")}


# Well-known port -> likely service. Used ONLY as a labeled, low-confidence
# hint when protocol probing told us nothing.
_PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle-db", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb", 11211: "memcached",
}


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

def fingerprint(ip: str, port: int, timeout: float = 3.0) -> dict:
    """Identify the service on an open port. Returns a result dict."""
    banner_bytes = _grab_banner(ip, port, timeout)
    banner = banner_bytes.decode("utf-8", errors="replace").strip()

    # 1) Try protocol grammars against the passive banner.
    for parser in (_parse_ssh, _parse_ftp, _parse_smtp, _parse_http_response):
        hit = parser(banner)
        if hit:
            hit.update({"port": port, "banner": banner[:BANNER_MAX]})
            return hit

    # 2) Active HTTP probe (benign HEAD request). Cheap and read-only, so we
    #    always try it once — a web server on a non-standard port is common.
    resp = _http_probe(ip, port, timeout).decode("utf-8", errors="replace")
    hit = _parse_http_response(resp)
    if hit:
        hit.update({"port": port,
                    "banner": (banner or resp.strip())[:BANNER_MAX],
                    "method": hit["method"] + " via active probe"})
        return hit

    # 2b) TLS handshake attempt — a TLS service won't answer the plaintext
    #     probes above, so try one real (read-only) handshake. Light mode:
    #     single handshake, no old-protocol probes (the engine runs the full
    #     TLS analysis later if this hits).
    tls = tlscheck.analyze_tls(ip, port, timeout=timeout, light=True)
    if not tls.get("error"):
        subject = tls.get("cert_subject") or "unknown subject"
        return {"port": port, "service": "https", "product": None,
                "version": tls.get("tls_version"), "confidence": 90,
                "method": f"TLS handshake completed ({tls.get('tls_version')})",
                "banner": f"cert: {subject}"[:BANNER_MAX]}

    # 3) Port-number hint — explicitly unverified.
    hint = _PORT_HINTS.get(port)
    if hint:
        return {"port": port, "service": hint, "product": None, "version": None,
                "confidence": 45, "method": "port-number hint (unverified)",
                "banner": banner[:BANNER_MAX]}

    # 4) Unknown — something answered, but we can't identify it. Say so.
    return {"port": port, "service": "unknown", "product": None, "version": None,
            "confidence": 15, "method": "no recognizable protocol behavior",
            "banner": banner[:BANNER_MAX]}
