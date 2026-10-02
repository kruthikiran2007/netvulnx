"""Rules over UDP service discovery (Milestone 19).

A UDP port is only recorded when a probe got a well-formed protocol
response — so a recorded UDP service is a confirmed observation, and
"open|filtered" silence is never stored. Confidence here is therefore
"confirmed" for the observation itself.
"""
import json


def _probe(ctx):
    row = (ctx.get("checks") or {}).get("udp_probe")
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    port = ctx.get("port")
    if port is None or getattr(port, "protocol", "tcp") != "udp":
        return None
    return d


def _match_snmp_public(ctx):
    d = _probe(ctx)
    if not d or d.get("service") != "snmp":
        return None
    details = d.get("details") or {}
    if details.get("community") != "public":
        return None
    return {
        "port": d.get("port"),
        "community": "public",
        "sysDescr": details.get("sysDescr", "(not disclosed)"),
        "_finding": {
            "title": "SNMP answers with the default 'public' community",
            "severity": "high",
            "description": (
                f"UDP/{d.get('port')}: the SNMP agent answered a GetRequest "
                f"using the well-known community string 'public'. "
                f"sysDescr: {details.get('sysDescr', '(not disclosed)')[:200]}"),
        },
    }


def _match_udp_exposed(ctx):
    d = _probe(ctx)
    if not d:
        return None
    if d.get("service") == "snmp" and \
            (d.get("details") or {}).get("community") == "public":
        return None  # covered by the sharper snmp-public-community rule
    return {
        "port": d.get("port"),
        "service": d.get("service"),
        "_finding": {
            "title": f"UDP service exposed: {d.get('service')}",
            "severity": "info",
            "description": (
                f"UDP/{d.get('port')} answered a protocol probe for "
                f"{d.get('service')} — the service is confirmed running. "
                f"Details: {json.dumps(d.get('details') or {})[:200]}"),
        },
    }


RULES = [
    {
        "id": "snmp-public-community",
        "title": "SNMP answers with the default 'public' community",
        "severity": "high",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": ("Default SNMP communities let anyone read device "
                   "configuration, network topology, running processes and "
                   "sometimes write access — a classic foothold for "
                   "lateral movement."),
        "remediation": ("Change the community strings to long random "
                        "values, restrict SNMP to management hosts via ACL, "
                        "and prefer SNMPv3 with authentication and privacy."),
        "references": ["https://www.cisa.gov/news-events/alerts/2017/04/27/"
                       "securing-network-infrastructure-devices"],
        "match": _match_snmp_public,
    },
    {
        "id": "udp-service-exposed",
        "title": "UDP service exposed",
        "severity": "info",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": ("A confirmed UDP service is part of the attack surface; "
                   "whether it matters depends on the service and its "
                   "configuration."),
        "remediation": ("Verify each exposed UDP service is needed on this "
                        "host; disable or firewall the rest."),
        "references": ["https://nmap.org/book/scan-methods-udp-scan.html"],
        "match": _match_udp_exposed,
    },
]
