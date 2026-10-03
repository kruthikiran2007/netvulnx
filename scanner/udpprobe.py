# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""UDP service discovery (Milestone 19).

UDP has no handshake, so "is this port open?" is fundamentally uncertain:
a silent port may be closed, filtered, or just dropping our probe. This
module is honest about that:

- A port is reported "open" ONLY when we receive a well-formed response
  to a protocol-specific probe (DNS, SNMP, NTP, NetBIOS-NS).
- Anything else is "open|filtered" and is NOT stored as a finding or a
  port row — silence is not evidence.

All probes are read-only: a version query, an SNMP GetRequest with the
"public" community (the same read the whole world does), an NTP client
request, a NetBIOS node-status query. No raw sockets, no ICMP parsing —
this works unprivileged.

Each probe is (build_query, parse_response). parse_response returns a
dict of extracted facts on success, or None when the reply isn't a valid
answer to our question.
"""
import random
import socket
import struct

#: UDP ports probed on every asset (config-overridable via
#: Config.DEFAULT_UDP_PORTS).
DEFAULT_UDP_PORTS = (53, 123, 137, 161)

TIMEOUT = 2.0
RETRIES = 2


# ---------------------------------------------------------------- DNS (53)

def _dns_query():
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    qname = b"\x07version\x04bind\x00"
    question = qname + struct.pack(">HH", 16, 3)  # TXT, CHAOS
    return txid, header + question


def _dns_parse(data, txid):
    if len(data) < 12:
        return None
    r_txid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if r_txid != txid or not (flags & 0x8000) or an == 0:
        return None
    # Find the TXT answer: skip question, then walk records for type 16.
    off = 12
    try:
        while data[off] != 0:
            off += 1 + data[off]
        off += 5  # null + QTYPE + QCLASS
        for _ in range(an):
            while off + 10 <= len(data):
                if data[off] & 0xC0 == 0xC0:  # compressed name pointer
                    off += 2
                    break
                if data[off] == 0:
                    off += 1
                    break
                off += 1 + data[off]
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            rdata = data[off + 10:off + 10 + rdlen]
            off += 10 + rdlen
            if rtype == 16 and rdata:
                # TXT: one or more <len><string> chunks.
                txt, i = "", 0
                while i < len(rdata):
                    ln = rdata[i]
                    txt += rdata[i + 1:i + 1 + ln].decode(
                        "ascii", errors="replace")
                    i += 1 + ln
                return {"version": txt[:100]}
    except (IndexError, struct.error):
        return None
    return None


# --------------------------------------------------------------- SNMP (161)

def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _snmp_query():
    # SNMPv2c GetRequest for sysDescr.0, community "public".
    oid = bytes([0x06, 0x09, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = _ber_tlv(0x30, oid + _ber_tlv(0x05, b""))
    varbinds = _ber_tlv(0x30, varbind)
    req_id = _ber_tlv(0x02, random.randint(1, 2 ** 31 - 1).to_bytes(4, "big"))
    pdu = _ber_tlv(0xA2, req_id + _ber_tlv(0x02, b"\x00") +
                   _ber_tlv(0x02, b"\x00") + varbinds)
    msg = _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, b"public") + pdu
    return None, _ber_tlv(0x30, msg)


def _snmp_parse(data, _txid):
    # An SNMP message is a SEQUENCE; a GetResponse PDU has tag 0xA2.
    if len(data) < 20 or data[0] != 0x30 or 0xA2 not in data[:30]:
        return None
    info = {"community": "public"}
    # Best-effort sysDescr extraction: first long printable string.
    best = ""
    i = 0
    while i < len(data) - 4:
        if data[i] == 0x04:  # OCTET STRING
            ln = data[i + 1]
            if ln < 128 and i + 2 + ln <= len(data):
                s = data[i + 2:i + 2 + ln]
                try:
                    t = s.decode("ascii")
                    if len(t) > len(best) and all(
                            32 <= c < 127 for c in t.encode()):
                        best = t
                except UnicodeDecodeError:
                    pass
                i += 2 + ln
                continue
        i += 1
    if best and best != "public":
        info["sysDescr"] = best[:200]
    return info


# ---------------------------------------------------------------- NTP (123)

def _ntp_query():
    # LI=0, VN=4, Mode=3 (client). Rest zeroed.
    return None, bytes([0x23] + [0] * 47)


def _ntp_parse(data, _txid):
    if len(data) < 48:
        return None
    li_vn_mode, stratum = data[0], data[1]
    if (li_vn_mode & 0x07) != 4 or stratum == 0:  # not a server reply
        return None
    return {"version": (li_vn_mode >> 3) & 0x07, "stratum": stratum}


# ---------------------------------------------------------- NetBIOS-NS (137)

def _nbns_query():
    txid = random.randint(0, 65535)
    # Encoded name for "*" (0x2A) + 14 spaces + suffix 0x00.
    raw = b"\x2A" + b"\x20" * 14 + b"\x00"
    encoded = "".join(chr(0x41 + (b >> 4)) + chr(0x41 + (b & 0x0F))
                      for b in raw).encode("ascii")
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    question = bytes([32]) + encoded + b"\x00" + struct.pack(">HH", 33, 1)
    return txid, header + question


def _nbns_parse(data, txid):
    if len(data) < 12:
        return None
    r_txid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if r_txid != txid or an == 0:
        return None
    return {"answers": an, "authoritative": bool(flags & 0x0400)}


PROBES = {
    53: ("dns", _dns_query, _dns_parse),
    123: ("ntp", _ntp_query, _ntp_parse),
    137: ("nbns", _nbns_query, _nbns_parse),
    161: ("snmp", _snmp_query, _snmp_parse),
}


def probe_udp(ip, port, timeout=TIMEOUT, retries=RETRIES):
    """Probe one UDP port. Returns a result dict, never raises.

    result = {"port":, "service":, "state": "open" | "open|filtered",
              "details": {...}} — details only on a confirmed response.
    """
    name, build, parse = PROBES.get(port, (f"udp-{port}", None, None))
    result = {"port": port, "service": name, "state": "open|filtered",
              "details": {}}
    if build is None:
        return result  # no probe for this port: honest silence
    txid, query = build()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for _ in range(retries):
            try:
                sock.sendto(query, (ip, port))
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            facts = parse(data, txid)
            if facts is not None:
                result["state"] = "open"
                result["details"] = facts
                break
    except OSError:
        pass
    finally:
        sock.close()
    return result


def discover_udp(ip, ports=None, timeout=TIMEOUT):
    """Probe the standard UDP ports; return only confirmed-open services."""
    return [r for r in (probe_udp(ip, p, timeout) for p in
                        (ports or DEFAULT_UDP_PORTS))
            if r["state"] == "open"]
