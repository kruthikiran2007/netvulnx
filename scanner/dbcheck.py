"""Database greeting checks (Milestone 21).

Three read-only probes that never authenticate and never send credentials:

MySQL (3306): the server speaks first — it sends a handshake packet that
    starts with a protocol version byte and a null-terminated version
    string (e.g. "8.0.36" or "10.11.7-MariaDB"). We read just that packet
    and disconnect. No login attempted.

PostgreSQL (5432): we send an SSLRequest (8 bytes, the standard
    pre-authentication probe every psql client sends) and read the
    single-byte reply: 'S' means the server supports TLS, 'N' means it
    does not. We then disconnect without starting a session.

Redis (6379): we send "PING" and read the reply. "+PONG" means the
    server answers without authentication (a classic exposure);
    "-NOAUTH"/"-ERR ... auth ..." means a password is required (good).
    We never run any other command.
"""
import re
import socket
import struct

from config import Config

TIMEOUT = getattr(Config, "SERVICE_CHECK_TIMEOUT", 5.0)


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-read")
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# MySQL
# --------------------------------------------------------------------------
def check_mysql(host, port=3306, timeout=TIMEOUT):
    """Read the MySQL/MariaDB server handshake; return version info."""
    result = {"protocol": "mysql", "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # MySQL packet header: 3-byte little-endian length + 1-byte sequence.
        header = _read_exact(sock, 4)
        length = int.from_bytes(header[:3], "little")
        if length > 65536 or length < 10:
            raise OSError(f"implausible handshake length {length}")
        payload = _read_exact(sock, length)
        if payload[0] != 10:
            # 0xFF would be an error packet; anything else is not MySQL.
            raise OSError(f"unexpected handshake protocol byte {payload[0]}")
        # Null-terminated server version string follows the protocol byte.
        end = payload.index(b"\x00", 1)
        version = payload[1:end].decode("ascii", errors="replace")
        result.update({
            "server_version": version,
            "is_mariadb": "mariadb" in version.lower(),
            "summary": f"MySQL handshake: server version {version}",
        })
    except (OSError, ValueError, IndexError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return result


def parse_mysql_version(version):
    """Split '8.0.36' / '10.11.7-MariaDB-1:10.11.7+maria~ubu2204' into
    (flavor, major, minor). Returns (None, None, None) if unparseable."""
    if not version:
        return None, None, None
    flavor = "mariadb" if "mariadb" in version.lower() else "mysql"
    m = re.search(r"(\d+)\.(\d+)", version)
    if not m:
        return flavor, None, None
    return flavor, int(m.group(1)), int(m.group(2))


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------
# SSLRequest: Int32 length (8) + Int32 request code (80877103).
_PG_SSL_REQUEST = struct.pack(">II", 8, 80877103)


def check_postgres(host, port=5432, timeout=TIMEOUT):
    """Send SSLRequest; report whether the server offers TLS."""
    result = {"protocol": "postgres", "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_PG_SSL_REQUEST)
        reply = _read_exact(sock, 1)
        if reply == b"S":
            result.update({
                "ssl_supported": True,
                "summary": "PostgreSQL offers TLS (SSLRequest -> 'S')",
            })
        elif reply == b"N":
            result.update({
                "ssl_supported": False,
                "summary": "PostgreSQL does NOT offer TLS (SSLRequest -> 'N')",
            })
        else:
            raise OSError(f"unexpected SSLRequest reply {reply!r}")
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return result


# --------------------------------------------------------------------------
# Redis
# --------------------------------------------------------------------------
def check_redis(host, port=6379, timeout=TIMEOUT):
    """Send PING; report whether the server answers without auth."""
    result = {"protocol": "redis", "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"PING\r\n")
        # Read one line of the RESP reply.
        buf = b""
        while len(buf) < 512 and not buf.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
        line = buf.decode("ascii", errors="replace").strip()
        if line == "+PONG":
            result.update({
                "auth_required": False,
                "summary": "Redis answered PING without authentication",
            })
        elif "auth" in line.lower():
            result.update({
                "auth_required": True,
                "reply": line[:120],
                "summary": "Redis requires authentication",
            })
        elif not line:
            raise OSError("empty reply to PING")
        else:
            result.update({
                "auth_required": None,
                "reply": line[:120],
                "summary": f"Redis unexpected reply: {line[:60]}",
            })
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return result
