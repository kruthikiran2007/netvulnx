"""RDP protocol analyzer (Milestone 20).

What this does: opens a TCP connection to the RDP port and performs the
same X.224 connection handshake every RDP client does — no credentials,
no login, no session. We send a Connection Request asking for the
strongest protocols (TLS, CredSSP/NLA) and read the server's Connection
Confirm to see what it actually selected:

  selected = 0 (PROTOCOL_RDP)      -> plain RDP security, no TLS
  selected = 1 (PROTOCOL_SSL)      -> TLS, but no Network Level Auth
  selected = 2/8 (HYBRID/HYBRID_EX)-> TLS + CredSSP Network Level Auth

The handshake is read-only: we disconnect right after the confirm.
Fully benign — identical to what mstsc does before showing the login box.

Wire format: TPKT (RFC 1006) + X.224 Connection Request/Confirm,
with the RDP Negotiation Request/Response (MS-RDPBCGR 2.2.1.1/2.2.1.2).
"""
import socket
import struct

from config import Config

TIMEOUT = getattr(Config, "SERVICE_CHECK_TIMEOUT", 5.0)

# requestedProtocols bits (MS-RDPBCGR 2.2.1.1.1)
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008

_SELECTED_NAMES = {
    PROTOCOL_RDP: "plain RDP (no TLS)",
    PROTOCOL_SSL: "TLS without NLA",
    PROTOCOL_HYBRID: "TLS + CredSSP (NLA)",
    PROTOCOL_HYBRID_EX: "TLS + CredSSP with early auth (NLA)",
}


def _connection_request() -> bytes:
    """X.224 Connection Request asking for TLS / NLA."""
    # RDP Negotiation Request: type=1, flags=0, length=8, protocols (LE).
    rdp_neg = struct.pack("<BBHI", 0x01, 0x00, 8,
                          PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)
    # X.224 CR: LI, type 0xE0, dst-ref, src-ref, class 0.
    x224 = struct.pack(">BBHHB", 6 + len(rdp_neg), 0xE0, 0, 0, 0) + rdp_neg
    # TPKT: version 3, reserved 0, total length (BE).
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224))
    return tpkt + x224


def _read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-handshake")
        buf += chunk
    return buf


def _read_tpkt(sock) -> bytes:
    """Read one TPKT packet; return its payload."""
    hdr = _read_exact(sock, 4)
    if hdr[0] != 3:
        raise OSError(f"not a TPKT packet (version {hdr[0]})")
    length = int.from_bytes(hdr[2:4], "big")
    if length < 7 or length > 65535:
        raise OSError(f"absurd TPKT length {length}")
    return _read_exact(sock, length - 4)


def _parse_connection_confirm(payload: bytes) -> dict:
    """Parse X.224 Connection Confirm. Returns negotiation outcome."""
    if len(payload) < 7:
        raise OSError("truncated X.224 confirm")
    if payload[1] != 0xD0:
        raise OSError(f"not a Connection Confirm (type 0x{payload[1]:02x})")
    out = {"selected_protocol": None, "negotiation_failure": None}
    # Optional RDP Negotiation Response starts after the 7-byte X.224 CC.
    rest = payload[7:]
    if len(rest) >= 8:
        (ntype, _flags, _length) = struct.unpack_from("<BBH", rest, 0)
        if ntype == 0x02:  # TYPE_RDP_NEG_RSP
            (selected,) = struct.unpack_from("<I", rest, 4)
            out["selected_protocol"] = selected
        elif ntype == 0x03:  # TYPE_RDP_NEG_FAILURE
            (code,) = struct.unpack_from("<I", rest, 4)
            out["negotiation_failure"] = code
    return out


def check_rdp(ip: str, port: int = 3389, timeout: float = TIMEOUT) -> dict:
    """Negotiate with an RDP server without authenticating.

    Returns a dict with keys: error, selected_protocol,
    selected_name, summary.
    """
    result = {"error": None, "selected_protocol": None, "selected_name": None}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_connection_request())
            payload = _read_tpkt(sock)
        parsed = _parse_connection_confirm(payload)
    except (OSError, struct.error) as exc:
        result["error"] = f"RDP handshake failed: {exc}"
        result["summary"] = result["error"]
        return result

    if parsed["negotiation_failure"] is not None:
        # Server refused our protocols; e.g. SSL_REQUIRED_BY_SERVER (1)
        # means it insists on TLS — the safe outcome.
        result["selected_protocol"] = -1
        result["selected_name"] = (
            "negotiation refused by server "
            f"(code 0x{parsed['negotiation_failure']:08x})")
    elif parsed["selected_protocol"] is not None:
        sel = parsed["selected_protocol"]
        result["selected_protocol"] = sel
        result["selected_name"] = _SELECTED_NAMES.get(
            sel, f"unknown protocol 0x{sel:08x}")
    else:
        # No negotiation block at all: classic plain-RDP server.
        result["selected_protocol"] = PROTOCOL_RDP
        result["selected_name"] = _SELECTED_NAMES[PROTOCOL_RDP]

    result["summary"] = f"RDP selected: {result['selected_name']}"
    return result
