"""Unit tests for target parsing and scope validation.

Run with:  python -m pytest tests/ -v   (from the project folder)

These tests never touch the real network — DNS lookups are faked with
unittest.mock so the tests pass identically on any machine, online or not.
"""
import socket
from unittest.mock import patch

import pytest

from scanner.targets import parse_target, parse_ports, TargetError


# ---------- valid targets ----------

def test_single_loopback_ip():
    t = parse_target("127.0.0.1")
    assert t["type"] == "ip"
    assert t["hosts"] == ["127.0.0.1"]


def test_private_ip_allowed():
    t = parse_target("192.168.56.101")
    assert t["type"] == "ip"
    assert t["hosts"] == ["192.168.56.101"]


def test_valid_cidr_24():
    t = parse_target("192.168.1.0/24")
    assert t["type"] == "cidr"
    assert len(t["hosts"]) == 254  # .0 and .255 are network/broadcast
    assert t["hosts"][0] == "192.168.1.1"


def test_localhost_hostname_resolves_and_is_allowed():
    t = parse_target("localhost")
    assert t["type"] == "hostname"
    assert t["hosts"] == ["127.0.0.1"]


# ---------- invalid / out-of-scope targets ----------

def test_public_ip_rejected_by_default():
    with pytest.raises(TargetError, match="outside the allowed scope"):
        parse_target("8.8.8.8")


def test_public_ip_allowed_with_explicit_opt_in():
    t = parse_target("8.8.8.8", allow_public=True)
    assert t["hosts"] == ["8.8.8.8"]


def test_cidr_too_large_rejected():
    with pytest.raises(TargetError, match="too large"):
        parse_target("10.0.0.0/8")


def test_malformed_cidr_rejected():
    with pytest.raises(TargetError, match="not a valid CIDR"):
        parse_target("192.168.1.0/33")


def test_unresolvable_hostname_rejected():
    # Fake DNS failure: gethostbyname raises, exactly like a real NXDOMAIN.
    with patch("scanner.targets.socket.gethostbyname",
               side_effect=socket.gaierror):
        with pytest.raises(TargetError, match="Could not resolve"):
            parse_target("this-host-definitely-does-not-exist-12345.invalid")


def test_hostname_resolving_outside_scope_rejected():
    # Even if DNS answers, the scope check must still reject public IPs.
    with patch("scanner.targets.socket.gethostbyname", return_value="8.8.8.8"):
        with pytest.raises(TargetError, match="outside the allowed scope"):
            parse_target("example.com")


def test_empty_target_rejected():
    with pytest.raises(TargetError, match="Please enter a target"):
        parse_target("   ")


# ---------- port parsing ----------

def test_port_list():
    assert parse_ports("80,443") == [80, 443]


def test_port_range():
    assert parse_ports("20-22") == [20, 21, 22]


def test_mixed_ports_sorted_unique():
    assert parse_ports("443, 20-21, 80, 20") == [20, 21, 80, 443]


def test_port_zero_rejected():
    with pytest.raises(TargetError, match="not a valid port"):
        parse_ports("0")


def test_port_too_high_rejected():
    with pytest.raises(TargetError, match="not a valid port"):
        parse_ports("70000")


def test_backwards_range_rejected():
    with pytest.raises(TargetError, match="invalid"):
        parse_ports("100-20")


def test_too_many_ports_rejected():
    with pytest.raises(TargetError, match="Too many ports"):
        parse_ports("1-2000")  # limit is 1024 ports per scan


def test_1024_ports_allowed():
    ports = parse_ports("1-1024")
    assert len(ports) == 1024
