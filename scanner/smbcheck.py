"""SMB protocol analyzer (Milestone 20).

What this does: opens a TCP connection to the SMB port and performs the
same negotiation every SMB client does — no authentication, no session
setup, no file access. Two handshakes:

1. SMB2 NEGOTIATE — asks the server which SMB 2.x/3.x dialect it picks and
   whether it requires message signing. Signing not required -> relay
   attacks (e.g. NTLM relay) are possible.
2. SMB1 NEGOTIATE (SMB_COM_NEGOTIATE) — checks whether the ancient SMBv1
   dialect is still accepted. SMBv1 is deprecated and was the vector for
   WannaCry/EternalBlue; it must be off.

Both handshakes are read-only protocol hellos. We never send credentials
and we disconnect right after the negotiate response.

Wire format references (public specs):
  MS-SMB2 section 2.2.3/2.2.4  (NEGOTIATE Request/Response)
  MS-CIFS section 2.2.4.5.2.1  (SMB_COM_NEGOTIATE)
  NetBIOS Session Service: 1-byte type 0x00 + 3-byte big-endian length.
"""
import socket
import struct

from config import Config

TIMEOUT = getattr(Config, "SERVICE_CHECK_TIMEOUT", 5.0)

# SMB2 dialects we offer, newest first (uint16 values).
_SMB2_DIALECTS = (0x0311, 0x0302, 0x0300, 0x0210, 0x0202)
_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1",
    0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
}

# SecurityMode bits in the NEGOTIATE response (MS-SMB2 2.2.4).
_SMB2_SIGNING_ENABLED = 0x01
_SMB2_SIGNING_REQUIRED = 0x02


def _nbss_wrap(payload: bytes) -> bytes:
    """Prefix a NetBIOS Session Service header (type 0x00)."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command: int = 0) -> bytes:
    """64-byte SMB2 header for a NEGOTIATE request."""
    return struct.pack(
        "<4s H H I H H I I Q I I Q 16s",
        b"\xfeSMB",        # ProtocolId
        64,                # HeaderLength
        0,                 # CreditCharge
        0,                 # Status
        command,           # Command (0 = NEGOTIATE)
        1,                 # Credits requested
        0x00000001,        # Flags
        0,                 # ChainOffset
        0,                 # MessageId
        0xFEFF,            # ProcessId (arbitrary)
        0,                 # TreeId
        0,                 # SessionId
        b"\x00" * 16,      # Signature
    )


def _smb2_negotiate_request() -> bytes:
    dialects = _SMB2_DIALECTS
    body = struct.pack(
        "<H H H H I 16s I H H",
        36,                # StructureSize
        len(dialects),     # DialectCount
        0x0003,            # SecurityMode: signing enabled+required (we offer)
        0,                 # Reserved
        0x00000007,        # Capabilities (DFS | LEASING | LARGE_MTU)
        b"\x00" * 16,      # ClientGuid
        0,                 # NegotiateContextOffset
        0,                 # NegotiateContextCount
        0,                 # Reserved2
    )
    for d in dialects:
        body += struct.pack("<H", d)
    return _nbss_wrap(_smb2_header(0) + body)


def _smb1_negotiate_request() -> bytes:
    """SMB_COM_NEGOTIATE asking only for the NT LM 0.12 (SMBv1) dialect."""
    smb_header = struct.pack(
        "<4s B B B H B H H 8s H H H H H",
        b"\xffSMB",        # Protocol
        0x72,              # Command = SMB_COM_NEGOTIATE
        0,                 # ErrorClass
        0,                 # Reserved
        0,                 # ErrorCode
        0x18,              # Flags
        0xC001,            # Flags2 (unicode + NT status)
        0,                 # PIDHigh
        b"\x00" * 8,       # SecurityFeatures
        0,                 # Reserved2
        0,                 # TID
        0xFEFF,            # PID
        0,                 # UID
        0,                 # MID
    )
    dialect = b"\x02NT LM 0.12\x00"
    body = struct.pack("<B H", 0, len(dialect)) + dialect  # WordCount, ByteCount
    return _nbss_wrap(smb_header + body)


def _read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-packet")
        buf += chunk
    return buf


def _read_nbss(sock) -> bytes:
    """Read one NetBIOS Session Service message; return its payload."""
    hdr = _read_exact(sock, 4)
    if hdr[0] != 0x00:
        raise OSError(f"unexpected NetBIOS message type 0x{hdr[0]:02x}")
    length = int.from_bytes(hdr[1:4], "big")
    if length > 1_000_000:
        raise OSError(f"absurd NetBIOS length {length}")
    return _read_exact(sock, length)


def _parse_smb2_negotiate_response(payload: bytes) -> dict:
    """Parse an SMB2 NEGOTIATE response. Raises OSError on garbage."""
    if len(payload) < 64 + 2:
        raise OSError("truncated SMB2 response")
    if payload[0:4] != b"\xfeSMB":
        raise OSError("not an SMB2 response")
    (status,) = struct.unpack_from("<I", payload, 8)
    (command,) = struct.unpack_from("<H", payload, 12)
    if command != 0:
        raise OSError(f"unexpected SMB2 command {command}")
    if status != 0:
        raise OSError(f"SMB2 negotiate failed, status 0x{status:08x}")
    body = payload[64:]
    (struct_size, sec_mode, dialect) = struct.unpack_from("<H H H", body, 0)
    if struct_size != 65:
        raise OSError(f"unexpected negotiate struct size {struct_size}")
    return {"security_mode": sec_mode, "dialect": dialect}


def _parse_smb1_negotiate_response(payload: bytes):
    """Return True if the server accepted our SMBv1 dialect."""
    if len(payload) < 32 + 3:
        raise OSError("truncated SMB1 response")
    if payload[0:4] != b"\xffSMB":
        raise OSError("not an SMB1 response")
    (word_count,) = struct.unpack_from("<B", payload, 32)
    if word_count in (13, 17):
        (dialect_index,) = struct.unpack_from("<H", payload, 33)
        return dialect_index != 0xFFFF
    # Any other WordCount (e.g. an error response) means "no".
    return False


def check_smb(ip: str, port: int = 445, timeout: float = TIMEOUT) -> dict:
    """Negotiate with an SMB server without authenticating.

    Returns a dict with keys: error, dialect, dialect_name,
    signing_enabled, signing_required, smbv1_enabled, summary.
    """
    result = {
        "error": None,
        "dialect": None,
        "dialect_name": None,
        "signing_enabled": None,
        "signing_required": None,
        "smbv1_enabled": None,
    }

    # --- Handshake 1: SMB2 negotiate -------------------------------------
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_smb2_negotiate_request())
            resp = _read_nbss(sock)
        parsed = _parse_smb2_negotiate_response(resp)
    except (OSError, struct.error) as exc:
        result["error"] = f"SMB2 negotiate failed: {exc}"
        result["summary"] = result["error"]
        return result

    sec = parsed["security_mode"]
    result["dialect"] = parsed["dialect"]
    result["dialect_name"] = _DIALECT_NAMES.get(
        parsed["dialect"], f"unknown (0x{parsed['dialect']:04x})")
    result["signing_enabled"] = bool(sec & _SMB2_SIGNING_ENABLED)
    result["signing_required"] = bool(sec & _SMB2_SIGNING_REQUIRED)

    # --- Handshake 2: SMB1 probe ------------------------------------------
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_smb1_negotiate_request())
            resp = _read_nbss(sock)
        result["smbv1_enabled"] = _parse_smb1_negotiate_response(resp)
    except (OSError, struct.error):
        # Server refused/ignored SMBv1 — that is the GOOD outcome.
        result["smbv1_enabled"] = False

    bits = [f"dialect {result['dialect_name']}"]
    bits.append("signing required" if result["signing_required"]
                else "signing NOT required")
    bits.append("SMBv1 enabled" if result["smbv1_enabled"]
                else "SMBv1 disabled")
    result["summary"] = "SMB: " + ", ".join(bits)
    return result
