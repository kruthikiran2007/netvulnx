"""Safe, read-only service-specific observations.

Each check completes the protocol's greeting and quits politely.
No data transfer, no mail sending, no real logins — with one deliberate
exception documented below.

Checks:
  - DNS  (port 53):  ask for version.bind (CHAOS TXT). A classic, harmless
                      query; many servers refuse it (which is itself the
                      observation: "does not disclose version").
  - SMTP (port 25):  banner + EHLO extensions + is STARTTLS advertised?
                      We do NOT test open relay — sending probe emails
                      through someone else's server is out of scope.
  - FTP  (port 21):  attempt an ANONYMOUS login (USER anonymous /
                      PASS anonymous@) and record the response code, then
                      QUIT. No directory listing, no download. Anonymous
                      FTP probing is standard assessment practice; the
                      observation is whether the server ALLOWS it.
"""
import random
import socket
import struct

BANNER_MAX = 500


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def _read_replyline(file) -> list:
    """Read a (possibly multiline) SMTP/FTP reply. '250-...' continues,
    '250 ' ends. Returns the lines."""
    lines = []
    while len(lines) < 50:
        line = file.readline(4096)
        if not line:
            break
        lines.append(line.rstrip("\r\n"))
        if len(line) >= 4 and line[3] == " ":
            break
    return lines


def _code(lines: list):
    """First reply's 3-digit code as int, or None."""
    if lines and len(lines[0]) >= 3 and lines[0][:3].isdigit():
        return int(lines[0][:3])
    return None


def _talk(host: str, port: int, timeout: float, script: list) -> dict:
    """Connect, run [(send, expect_note)...], return transcript lines.

    script: list of (bytes_to_send_or_None, description). After each send,
    read one reply block. Always attempts QUIT at the end (best effort).
    """
    transcript = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            f = sock.makefile("r", encoding="utf-8", errors="replace")
            greeting = _read_replyline(f)
            transcript.append(("greeting", greeting))
            for send, _note in script:
                if send:
                    sock.sendall(send)
                reply = _read_replyline(f)
                transcript.append((_note, reply))
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
    except Exception as exc:
        return {"transcript": transcript,
                "error": f"{type(exc).__name__}: {exc}"}
    return {"transcript": transcript, "error": None}


# --------------------------------------------------------------------------
# DNS: version.bind over TCP
# --------------------------------------------------------------------------

def _build_version_bind_query() -> tuple:
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD set
    question = b"\x07version\x04bind\x00" + struct.pack(">HH", 16, 3)  # TXT CH
    return txid, header + question


def _skip_dns_name(data: bytes, off: int) -> int:
    while off < len(data):
        length = data[off]
        if length & 0xC0 == 0xC0:   # compression pointer: 2 bytes, done
            return off + 2
        if length == 0:
            return off + 1
        off += 1 + length
    return off


def _parse_dns_response(data: bytes, txid: int) -> dict:
    if len(data) < 12:
        return {"version": None, "note": "truncated DNS response"}
    r_txid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if r_txid != txid:
        return {"version": None, "note": "transaction ID mismatch"}
    rcode = flags & 0x000F
    if rcode == 5:
        return {"version": None, "note": "server refused the query (REFUSED)"}
    if rcode != 0:
        return {"version": None, "note": f"DNS error code {rcode}"}
    off = 12
    for _ in range(qd):  # skip question section(s)
        off = _skip_dns_name(data, off) + 4
    for _ in range(an):  # walk answer RRs
        off = _skip_dns_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _class, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 16 and rdata:  # TXT
            texts = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                texts.append(rdata[i + 1:i + 1 + ln].decode("utf-8", errors="replace"))
                i += 1 + ln
            return {"version": " ".join(texts) or None,
                    "note": "server disclosed its version"}
    return {"version": None, "note": "no usable answer (server stays silent)"}


def check_dns_version(host: str, port: int = 53, timeout: float = 3.0) -> dict:
    """Ask a DNS server for version.bind. Never raises."""
    txid, query = _build_version_bind_query()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack(">H", len(query)) + query)
            ln_bytes = sock.recv(2)
            if len(ln_bytes) < 2:
                return {"version": None, "note": "no DNS response"}
            (ln,) = struct.unpack(">H", ln_bytes)
            data = b""
            while len(data) < ln:
                chunk = sock.recv(ln - len(data))
                if not chunk:
                    break
                data += chunk
    except Exception as exc:
        return {"version": None, "note": f"{type(exc).__name__}: {exc}"}
    return _parse_dns_response(data, txid)


# --------------------------------------------------------------------------
# SMTP: banner + EHLO extensions
# --------------------------------------------------------------------------

def check_smtp(host: str, port: int = 25, timeout: float = 5.0) -> dict:
    convo = _talk(host, port, timeout, [(b"EHLO netvulnx.local\r\n", "ehlo")])
    if convo["error"] and not convo["transcript"]:
        return {"error": convo["error"]}
    greeting = " ".join(convo["transcript"][0][1])[:BANNER_MAX]
    extensions = []
    for _note, lines in convo["transcript"][1:]:
        for line in lines:
            if len(line) > 4:
                extensions.append(line[4:].split()[0].upper())
    return {
        "error": convo["error"],
        "banner": greeting,
        "extensions": extensions,
        "starttls_advertised": "STARTTLS" in extensions,
        "summary": ("advertises STARTTLS" if "STARTTLS" in extensions
                    else "no STARTTLS advertised"),
    }


# --------------------------------------------------------------------------
# FTP: anonymous login attempt (no listing, no download)
# --------------------------------------------------------------------------

def check_ftp_anonymous(host: str, port: int = 21,
                        timeout: float = 5.0) -> dict:
    convo = _talk(host, port, timeout, [
        (b"USER anonymous\r\n", "user"),
        (b"PASS anonymous@\r\n", "pass"),
    ])
    if convo["error"] and not convo["transcript"]:
        return {"error": convo["error"]}
    greeting = " ".join(convo["transcript"][0][1])[:BANNER_MAX]
    user_code = _code(convo["transcript"][1][1]) if len(convo["transcript"]) > 1 else None
    pass_code = _code(convo["transcript"][2][1]) if len(convo["transcript"]) > 2 else None
    allowed = pass_code == 230
    return {
        "error": convo["error"],
        "banner": greeting,
        "user_response": user_code,
        "pass_response": pass_code,
        "anonymous_allowed": allowed,
        "summary": ("ANONYMOUS LOGIN ALLOWED" if allowed
                    else f"anonymous login denied (code {pass_code})"),
    }
