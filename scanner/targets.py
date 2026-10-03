# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Target parsing and scope validation.

This module answers two questions BEFORE any packet leaves the machine:
  1. Is the user's target text a valid IP, CIDR range, or hostname?
  2. Is the target inside the allowed scope (this machine + private/lab nets)?

Nothing in the scanner may run until both answers are "yes".
"""
import ipaddress
import socket


class TargetError(ValueError):
    """Raised when a target is invalid or out of scope.

    The message is written for humans and shown directly in the UI,
    so it must explain WHAT is wrong and HOW to fix it.
    """


# Networks we are allowed to scan by default: this machine + private LANs.
_ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),    # IPv4 loopback (this machine)
    ipaddress.ip_network("10.0.0.0/8"),     # private LAN
    ipaddress.ip_network("172.16.0.0/12"),  # private LAN
    ipaddress.ip_network("192.168.0.0/16"), # private LAN
    ipaddress.ip_network("::1/128"),        # IPv6 loopback (this machine)
]

MAX_PORTS_PER_SCAN = 1024


def _in_allowed_scope(ip, allow_public: bool) -> bool:
    """True if this IP may be scanned under the current safety settings."""
    if allow_public:
        # Explicit opt-in for authorized enterprise assessments.
        # Multicast / reserved / unspecified addresses are still never allowed.
        return not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    return any(ip in net for net in _ALLOWED_NETWORKS)


def _scope_rejection(what: str) -> TargetError:
    return TargetError(
        f"{what} is outside the allowed scope. By default NetVulnX only scans "
        "this machine (127.0.0.1) and private lab/LAN addresses "
        "(10.x.x.x, 172.16.x.x – 172.31.x.x, 192.168.x.x), to prevent "
        "accidental unauthorized scanning."
    )


def parse_target(text: str, allow_public: bool = False) -> dict:
    """Parse and validate a target string.

    Returns a dict:
        {"type": "ip" | "cidr" | "hostname",
         "hosts": ["192.168.1.1", ...],      # every host to check
         "network": "192.168.1.0/24" | None,
         "display": "human-readable summary"}
    Raises TargetError with a human-readable message on any problem.
    """
    text = (text or "").strip()
    if not text:
        raise TargetError("Please enter a target — an IP, a CIDR range, or a hostname.")

    # --- 1) Try a single IP address (v4 or v6) ---
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if ip is not None:
        if not _in_allowed_scope(ip, allow_public):
            raise _scope_rejection(text)
        return {"type": "ip", "hosts": [str(ip)], "network": None,
                "display": str(ip)}

    # --- 2) Try CIDR notation, e.g. 192.168.1.0/24 ---
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise TargetError(
                f"'{text}' is not a valid CIDR range. Example: 192.168.1.0/24"
            )
        # Keep default scans small and safe: /24 (256 addresses) for IPv4,
        # /120 (256 addresses) for IPv6. Bigger ranges risk overwhelming
        # a network by accident.
        min_prefix = 24 if net.version == 4 else 120
        if net.prefixlen < min_prefix:
            raise TargetError(
                f"'{text}' is too large. The default limit is /{min_prefix} "
                "(256 addresses) to avoid accidentally overwhelming a network."
            )
        hosts = [str(h) for h in net.hosts()]
        if not hosts:
            raise TargetError(f"'{text}' contains no usable host addresses.")
        # The whole network must sit inside the allowed scope — checking only
        # the first host is not enough (e.g. ::/120 starts at ::1 which is
        # allowed, but the other 254 addresses are not).
        if allow_public:
            # Explicit opt-in: still never allow multicast/reserved/unspecified.
            if net.is_multicast or net.is_reserved or net.is_unspecified:
                raise _scope_rejection(text)
        elif not any(net.version == allowed.version and net.subnet_of(allowed)
                     for allowed in _ALLOWED_NETWORKS):
            raise _scope_rejection(text)
        return {"type": "cidr", "hosts": hosts, "network": str(net),
                "display": f"{net} ({len(hosts)} hosts)"}

    # --- 3) Try a hostname: resolve it, then scope-check the result ---
    try:
        resolved = socket.gethostbyname(text)
    except socket.gaierror:
        raise TargetError(
            f"Could not resolve '{text}'. Check the spelling, or use an IP address."
        )
    if not _in_allowed_scope(ipaddress.ip_address(resolved), allow_public):
        raise TargetError(
            f"'{text}' resolves to {resolved}, which is outside the allowed scope."
        )
    return {"type": "hostname", "hosts": [resolved], "network": None,
            "display": f"{text} → {resolved}"}


def parse_ports(text: str, default: str = "80,443,22") -> list:
    """Parse '80,443' or '20-25,80' into a sorted list of port numbers."""
    text = (text or "").strip() or default
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise TargetError(
                    f"'{part}' is not a valid port range. Use the form 20-25."
                )
            if not (1 <= start <= 65535 and 1 <= end <= 65535) or end < start:
                raise TargetError(
                    f"Port range '{part}' is invalid. Ports run from 1 to 65535."
                )
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit() or not 1 <= int(part) <= 65535:
                raise TargetError(
                    f"'{part}' is not a valid port. Ports run from 1 to 65535."
                )
            ports.add(int(part))
    if not ports:
        raise TargetError("No ports to check. Examples: 80,443  or  1-100.")
    if len(ports) > MAX_PORTS_PER_SCAN:
        raise TargetError(
            f"Too many ports ({len(ports)}). The limit is "
            f"{MAX_PORTS_PER_SCAN} ports per scan, to keep checks sane."
        )
    return sorted(ports)
