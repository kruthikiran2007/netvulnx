# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for UDP service discovery (Milestone 19).

NOTE on this environment: the sandbox blocks UDP socket creation
(`Operation not permitted`), so live round-trip tests are skipped here
(they run wherever UDP is allowed). The protocol logic — query building
and response parsing — is fully tested without sockets by feeding each
probe's query bytes through a fake server function into its parser,
which exercises the exact same code path as the live probe.
"""
import socket
import struct
from types import SimpleNamespace

import pytest

from scanner import udpprobe
from rules import udp_rules


def _udp_available():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"\x00", ("127.0.0.1", 9))  # discard port; send must work
        s.close()
        return True
    except OSError:
        return False


needs_udp = pytest.mark.skipif(not _udp_available(),
                               reason="sandbox blocks UDP sockets")


# ------------------------------------------------------------------ helpers

def _dns_server(data):
    txid = struct.unpack(">H", data[:2])[0]
    qend = 12
    while data[qend] != 0:
        qend += 1 + data[qend]
    question = data[12:qend + 5]
    txt = b"FakeDNS 9.9"
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 60, len(txt) + 1)
              + bytes([len(txt)]) + txt)
    return struct.pack(">HHHHHH", txid, 0x8400, 1, 1, 0, 0) + question + answer


def _snmp_server(data):
    if not data or data[0] != 0x30:
        return None
    inner = (b"\x02\x01\x01" + b"\x04\x06public"
             + b"\xa2\x0f\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
               b"\x30\x00")
    descr = b"\x04\x0bFakeSNMP v1"
    return b"\x30" + bytes([len(inner) + len(descr) + 2]) + inner + descr


def _ntp_server(data):
    if len(data) < 48 or (data[0] & 0x07) != 3:
        return None
    return bytes([0x24, 0x02] + [0] * 46)


def _nbns_server(data):
    txid = struct.unpack(">H", data[:2])[0]
    return struct.pack(">HHHHHH", txid, 0x8400, 1, 1, 0, 0) + data[12:]


def _roundtrip(port, server_fn):
    """Run a probe's query through a fake server into its parser."""
    name, build, parse = udpprobe.PROBES[port]
    txid, query = build()
    assert isinstance(query, bytes) and len(query) > 0
    response = server_fn(query)
    assert response, f"fake server gave no reply for {name}"
    facts = parse(response, txid)
    assert facts is not None, f"parser rejected valid {name} response"
    return name, facts


# ------------------------------------------------- protocol logic, no sockets

def test_dns_roundtrip_logic():
    name, facts = _roundtrip(53, _dns_server)
    assert name == "dns"
    assert facts["version"] == "FakeDNS 9.9"


def test_snmp_roundtrip_logic():
    name, facts = _roundtrip(161, _snmp_server)
    assert name == "snmp"
    assert facts["community"] == "public"
    assert facts["sysDescr"] == "FakeSNMP v1"


def test_ntp_roundtrip_logic():
    name, facts = _roundtrip(123, _ntp_server)
    assert name == "ntp"
    assert facts["stratum"] == 2


def test_nbns_roundtrip_logic():
    name, facts = _roundtrip(137, _nbns_server)
    assert name == "nbns"
    assert facts["answers"] == 1


def test_parsers_reject_garbage():
    for port in (53, 123, 137, 161):
        _, build, parse = udpprobe.PROBES[port]
        txid, _ = build()
        assert parse(b"\xff" * 20, txid) is None, f"port {port}"
        assert parse(b"", txid) is None, f"port {port}"


def test_parsers_reject_wrong_txid():
    for port in (53, 137):
        _, build, parse = udpprobe.PROBES[port]
        txid, query = build()
        server = _dns_server if port == 53 else _nbns_server
        resp = server(query)
        assert parse(resp, (txid + 1) % 65536) is None


def test_probe_builders_are_wellformed():
    # DNS query asks version.bind TXT CHAOS; SNMP is a v2c GetRequest.
    _, query = udpprobe.PROBES[53][1]()
    assert b"version" in query and b"bind" in query
    _, query = udpprobe.PROBES[161][1]()
    assert query[0] == 0x30 and b"public" in query
    _, query = udpprobe.PROBES[123][1]()
    assert len(query) == 48 and query[0] == 0x23


# ------------------------------------------------- live sockets (skipped here)

@needs_udp
def test_live_dns_probe():
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(10)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def run():
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(4096)
                srv.sendto(_dns_server(data), addr)
            except socket.timeout:
                continue
    threading.Thread(target=run, daemon=True).start()
    udpprobe.PROBES[port] = udpprobe.PROBES[53]
    try:
        res = udpprobe.probe_udp("127.0.0.1", port, timeout=2.0)
    finally:
        del udpprobe.PROBES[port]
    stop.set()
    srv.close()
    assert res["state"] == "open"
    assert res["details"]["version"] == "FakeDNS 9.9"


@needs_udp
def test_live_silent_port_is_open_filtered():
    res = udpprobe.probe_udp("127.0.0.1", 161, timeout=0.5, retries=1)
    assert res["state"] == "open|filtered"
    assert res["details"] == {}


# --------------------------------------------------------------------- rules

def _ctx(port_num, service, details):
    row = SimpleNamespace(
        details=__import__("json").dumps(
            {"port": port_num, "service": service, "state": "open",
             "details": details}))
    port = SimpleNamespace(protocol="udp", port=port_num)
    return {"checks": {"udp_probe": row}, "port": port}


def test_snmp_public_community_rule():
    ctx = _ctx(161, "snmp", {"community": "public",
                             "sysDescr": "FakeSNMP v1"})
    by_id = {r["id"]: r for r in udp_rules.RULES}
    ev = by_id["snmp-public-community"]["match"](ctx)
    assert ev is not None
    assert ev["_finding"]["severity"] == "high"
    assert "public" in ev["_finding"]["title"]
    # the generic rule stays silent when the sharp one fires
    assert by_id["udp-service-exposed"]["match"](ctx) is None


def test_udp_exposed_rule_for_other_services():
    ctx = _ctx(123, "ntp", {"stratum": 2, "version": 4})
    by_id = {r["id"]: r for r in udp_rules.RULES}
    assert by_id["snmp-public-community"]["match"](ctx) is None
    ev = by_id["udp-service-exposed"]["match"](ctx)
    assert ev["_finding"]["severity"] == "info"
    assert "ntp" in ev["_finding"]["title"]


def test_udp_rules_ignore_tcp_ports():
    row = SimpleNamespace(details="{}")
    ctx = {"checks": {"udp_probe": row},
           "port": SimpleNamespace(protocol="tcp", port=80)}
    for r in udp_rules.RULES:
        assert r["match"](ctx) is None
