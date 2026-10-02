"""NoSQL / search-engine greeting checks (Milestone 22).

Three read-only probes that never authenticate and never write data:

MongoDB (27017): speaks the MongoDB wire protocol (OP_MSG). We send a
    `hello` command — the same handshake every driver sends — and then
    `buildInfo` for the version string. If the server answers without
    credentials, it is exposed.

Elasticsearch (9200): plain HTTP GET /. A 200 response with the
    familiar JSON body (name/cluster_name/version/tagline) and no 401
    means the cluster is open to the network.

Memcached (11211): the text protocol. We send `version` and read the
    `VERSION x.y.z` reply. Memcached has no authentication in its
    default configuration — a reply at all means it is exposed.
"""
import json as _json
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
# Minimal BSON helpers (just enough for hello / buildInfo replies)
# --------------------------------------------------------------------------
def _bson_cstring(s):
    return s.encode("utf-8") + b"\x00"


def _bson_doc(elements):
    """elements: list of (type_byte, name, value_bytes)."""
    body = b""
    for tbyte, name, val in elements:
        body += bytes([tbyte]) + _bson_cstring(name) + val
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _bson_int32(v):
    return struct.pack("<i", v)


def _bson_string(v):
    enc = v.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(enc)) + enc


def _bson_parse_doc(buf, pos=0):
    """Parse one BSON document; return (dict, new_pos). Handles the
    scalar types MongoDB returns for hello/buildInfo."""
    (total,) = struct.unpack_from("<i", buf, pos)
    end = pos + total
    pos += 4
    doc = {}
    while pos < end - 1:
        tbyte = buf[pos]
        pos += 1
        nend = buf.index(b"\x00", pos)
        name = buf[pos:nend].decode("utf-8", errors="replace")
        pos = nend + 1
        if tbyte == 0x01:  # double
            (v,) = struct.unpack_from("<d", buf, pos)
            pos += 8
        elif tbyte == 0x02:  # string
            (slen,) = struct.unpack_from("<i", buf, pos)
            v = buf[pos + 4:pos + 4 + slen - 1].decode("utf-8", errors="replace")
            pos += 4 + slen
        elif tbyte == 0x03:  # embedded document
            v, pos = _bson_parse_doc(buf, pos)
        elif tbyte == 0x04:  # array -> parse as list
            sub, pos = _bson_parse_doc(buf, pos)
            v = [sub[str(i)] for i in range(len(sub))]
        elif tbyte == 0x08:  # boolean
            v = buf[pos] == 1
            pos += 1
        elif tbyte == 0x10:  # int32
            (v,) = struct.unpack_from("<i", buf, pos)
            pos += 4
        elif tbyte == 0x12:  # int64
            (v,) = struct.unpack_from("<q", buf, pos)
            pos += 8
        else:
            raise OSError(f"unsupported BSON type 0x{tbyte:02x}")
        doc[name] = v
    return doc, end


def _op_msg(command_doc, db="admin", request_id=1):
    """Wrap a command document in an OP_MSG envelope (single kind-0 body
    section holding the full command plus $db)."""
    full = _bson_doc(command_doc + [(0x02, "$db", _bson_string(db))])
    section = b"\x00" + full
    header = struct.pack("<iii", 16 + 4 + len(section), request_id, 0)
    return header + struct.pack("<i", 2013) + struct.pack("<I", 0) + section


def _op_msg_reply(sock):
    """Read one OP_MSG reply; return the body document dict."""
    header = _read_exact(sock, 16)
    (length, _, _, opcode) = struct.unpack("<iiii", header)
    if opcode != 2013:
        raise OSError(f"expected OP_MSG, got opcode {opcode}")
    if length > 16 * 1024 * 1024:
        raise OSError(f"absurd reply length {length}")
    payload = _read_exact(sock, length - 16)
    if payload[4] != 0:  # flags, then first section kind must be 0 (body)
        raise OSError("unexpected OP_MSG sections")
    doc, _ = _bson_parse_doc(payload, 5)
    return doc


def check_mongodb(host, port=27017, timeout=TIMEOUT):
    """hello + buildInfo over the real wire protocol; no credentials."""
    result = {"protocol": "mongodb", "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_op_msg([(0x10, "hello", _bson_int32(1))]))
        hello = _op_msg_reply(sock)
        result["auth_required"] = False
        result["is_writable_primary"] = hello.get("isWritablePrimary")
        # Version comes from buildInfo (allowed without auth on open servers).
        try:
            sock.sendall(_op_msg([(0x10, "buildInfo", _bson_int32(1))], request_id=2))
            info = _op_msg_reply(sock)
            result["server_version"] = info.get("version")
        except OSError:
            pass
        result["summary"] = ("MongoDB answered hello without authentication" +
                             (f" (version {result['server_version']})"
                              if result.get("server_version") else ""))
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return result


# --------------------------------------------------------------------------
# Elasticsearch
# --------------------------------------------------------------------------
def check_elasticsearch(host, port=9200, timeout=TIMEOUT):
    """GET / and look for the Elasticsearch JSON banner."""
    result = {"protocol": "elasticsearch", "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        buf = b""
        while len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf and len(buf) > buf.index(b"\r\n\r\n") + 4:
                # crude but enough: we have headers; body follows
                pass
        text = buf.decode("utf-8", errors="replace")
        if "\r\n\r\n" not in text:
            raise OSError("no HTTP response")
        headers, _, body = text.partition("\r\n\r\n")
        status = headers.split("\r\n", 1)[0]
        if "401" in status:
            result.update({"auth_required": True,
                           "summary": "Elasticsearch requires authentication"})
            return result
        if "200" not in status:
            raise OSError(f"unexpected status: {status[:60]}")
        try:
            data = _json.loads(body)
        except ValueError:
            raise OSError("response is not JSON")
        if not isinstance(data, dict) or "tagline" not in data:
            raise OSError("not an Elasticsearch banner")
        version = (data.get("version") or {}).get("number")
        result.update({
            "auth_required": False,
            "server_version": version,
            "cluster_name": data.get("cluster_name"),
            "summary": (f"Elasticsearch {version or 'unknown version'} "
                        f"answers without authentication"),
        })
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return result


# --------------------------------------------------------------------------
# Memcached
# --------------------------------------------------------------------------
def check_memcached(host, port=11211, timeout=TIMEOUT):
    """Send `version`; a reply means the cache is network-exposed."""
    result = {"protocol": "memcached", "port": port}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"version\r\n")
        buf = b""
        while len(buf) < 256 and not buf.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
        line = buf.decode("ascii", errors="replace").strip()
        if not line.startswith("VERSION"):
            raise OSError(f"unexpected reply: {line[:60]}")
        version = line.split(None, 1)[1] if " " in line else ""
        result.update({
            "auth_required": False,  # memcached has no auth by default
            "server_version": version,
            "summary": f"Memcached {version} answers without authentication",
        })
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return result
