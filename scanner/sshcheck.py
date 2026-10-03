# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""SSH algorithm enumeration (Milestone 18).

What this does: opens a TCP connection, reads the server's version string,
sends our own version string, then reads the server's KEXINIT packet and
parses the algorithm lists it advertises (key exchange, host keys,
ciphers, MACs).

This is exactly what every SSH client does when connecting — no login is
attempted, no credentials are sent, and we disconnect immediately after
KEXINIT. Fully benign and read-only.

The SSH binary packet protocol (RFC 4253, section 6):
    uint32    packet_length        (not including these 4 bytes)
    byte      padding_length
    byte[]    payload
    byte[]    random padding
KEXINIT's payload starts with byte 20, a 16-byte cookie, then name-lists
(uint32 length + comma-separated names) for each algorithm category.
"""
import socket
import struct

from config import Config

SSH_MSG_KEXINIT = 20
TIMEOUT = getattr(Config, "SERVICE_CHECK_TIMEOUT", 5.0)
BANNER_MAX = 200


def _read_line(sock):
    """Read one \\n-terminated line (the version exchange)."""
    buf = b""
    while len(buf) < 255:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
        if buf.endswith(b"\n"):
            break
    return buf.decode("ascii", errors="replace").strip()


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-packet")
        buf += chunk
    return buf


def _read_packet(sock):
    """Read one SSH binary packet; return its payload bytes."""
    (packet_length,) = struct.unpack(">I", _read_exact(sock, 4))
    if packet_length > 35000:  # KEXINIT is small; anything huge is garbage
        raise OSError(f"absurd packet length {packet_length}")
    body = _read_exact(sock, packet_length)
    padding_length = body[0]
    payload = body[1:packet_length - padding_length]
    return payload


def _read_name_list(buf, off):
    (length,) = struct.unpack(">I", buf[off:off + 4])
    names = buf[off + 4:off + 4 + length].decode("ascii", errors="replace")
    return ([n for n in names.split(",") if n], off + 4 + length)


def _parse_kexinit(payload):
    """Parse a KEXINIT payload into a dict of algorithm lists."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise OSError("first packet was not KEXINIT")
    off = 1 + 16  # message code + cookie
    kex, off = _read_name_list(payload, off)
    hostkey, off = _read_name_list(payload, off)
    enc_c2s, off = _read_name_list(payload, off)
    enc_s2c, off = _read_name_list(payload, off)
    mac_c2s, off = _read_name_list(payload, off)
    mac_s2c, off = _read_name_list(payload, off)
    return {
        "kex_algorithms": kex,
        "host_key_algorithms": hostkey,
        "ciphers_c2s": enc_c2s,
        "ciphers_s2c": enc_s2c,
        "macs_c2s": mac_c2s,
        "macs_s2c": mac_s2c,
    }


def check_ssh_algorithms(host, port=22, timeout=TIMEOUT):
    """Enumerate an SSH server's algorithms. Returns a details dict.

    On any failure returns {"error": ...} — the caller records it and the
    scan continues. Never raises.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Servers may send banner lines before the version string.
            server_version = ""
            for _ in range(5):
                line = _read_line(sock)
                if line.startswith("SSH-"):
                    server_version = line
                    break
            if not server_version:
                return {"error": "no SSH version string received"}
            sock.sendall(b"SSH-2.0-NetVulnX_1.0\r\n")
            payload = _read_packet(sock)
            algos = _parse_kexinit(payload)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    algos["server_version"] = server_version[:BANNER_MAX]
    algos["summary"] = (
        f"{server_version[:60]} — {len(algos['kex_algorithms'])} kex, "
        f"{len(algos['ciphers_c2s'])} ciphers, {len(algos['macs_c2s'])} MACs")
    return algos
