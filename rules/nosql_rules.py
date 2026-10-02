"""Rules over the NoSQL / search-engine checks (Milestone 22).

The checks (scanner/nosqlcheck.py) never authenticate and never write:

  mongodb-no-auth              (high)   - hello answered, no credentials needed
  mongodb-eol-version          (medium) - 6.x and older are past end-of-life
  elasticsearch-no-auth        (high)   - GET / returned 200, no 401
  elasticsearch-old-version    (medium) - 7.x is past end-of-life
  memcached-exposed            (high)   - memcached answers; it has no auth
"""
import json
import re


def _check(ctx, check_type):
    row = (ctx.get("checks") or {}).get(check_type)
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    if d.get("error"):
        return None
    return d


def _major(version):
    m = re.search(r"(\d+)\.(\d+)", version or "")
    return int(m.group(1)) if m else None


def _match_mongo_no_auth(ctx):
    d = _check(ctx, "mongodb_hello")
    if not d or d.get("auth_required") is not False:
        return None
    return {
        "_finding": {
            "title": "MongoDB accepts commands without authentication",
            "severity": "high",
            "description": ("The server answered our hello command with no "
                            "credentials. Anyone on the network can read, "
                            "modify and delete databases" +
                            (f" (server version {d['server_version']})"
                             if d.get("server_version") else "") + "."),
            "impact": ("Full database compromise; exposed MongoDB instances "
                       "are routinely found by scanners and ransomed."),
            "remediation": ("Enable access control (--auth / security."
                            "authorization: enabled), create dedicated users "
                            "with least privilege, bind to localhost or a "
                            "private interface, firewall port 27017."),
        },
    }


def _match_mongo_eol(ctx):
    d = _check(ctx, "mongodb_hello")
    if not d or not d.get("server_version"):
        return None
    major = _major(d["server_version"])
    if major is None or major >= 7:
        return None
    return {
        "server_version": d["server_version"],
        "_finding": {
            "title": f"MongoDB {d['server_version']} is past end-of-life",
            "severity": "medium",
            "description": (f"The server reports version {d['server_version']}. "
                            "MongoDB 6.x and older receive no security fixes."),
            "impact": "Known, unpatched server vulnerabilities stay open.",
            "remediation": "Upgrade to a supported release (7.0+ / 8.x).",
        },
    }


def _match_es_no_auth(ctx):
    d = _check(ctx, "elasticsearch_banner")
    if not d or d.get("auth_required") is not False:
        return None
    return {
        "_finding": {
            "title": "Elasticsearch answers without authentication",
            "severity": "high",
            "description": ("GET / returned 200 with the cluster banner and "
                            "no 401 challenge" +
                            (f" (version {d['server_version']})"
                             if d.get("server_version") else "") + ". Anyone "
                            "on the network can read and write indices."),
            "impact": ("Full data compromise; exposed clusters are a "
                       "classic source of large public breaches."),
            "remediation": ("Enable the security features (xpack.security."
                            "enabled), set built-in user passwords, use TLS "
                            "between nodes, firewall port 9200."),
        },
    }


def _match_es_old(ctx):
    d = _check(ctx, "elasticsearch_banner")
    if not d or not d.get("server_version"):
        return None
    major = _major(d["server_version"])
    if major is None or major >= 8:
        return None
    return {
        "server_version": d["server_version"],
        "_finding": {
            "title": f"Elasticsearch {d['server_version']} is past end-of-life",
            "severity": "medium",
            "description": (f"The cluster reports version {d['server_version']}. "
                            "Elasticsearch 7.x is past end-of-life."),
            "impact": "Known, unpatched vulnerabilities stay open.",
            "remediation": "Upgrade to a supported 8.x release.",
        },
    }


def _match_memcached(ctx):
    d = _check(ctx, "memcached_version")
    if not d or d.get("auth_required") is not False:
        return None
    return {
        "_finding": {
            "title": "Memcached exposed to the network",
            "severity": "high",
            "description": ("The server answered our version probe" +
                            (f" (VERSION {d['server_version']})"
                             if d.get("server_version") else "") + ". "
                            "Memcached has no authentication in its default "
                            "configuration — anyone on the network can read "
                            "and poison cached data, and the UDP side is a "
                            "notorious DDoS amplifier."),
            "impact": "Cache data theft/poisoning; DDoS-amplification abuse.",
            "remediation": ("Bind memcached to localhost (-l 127.0.0.1), "
                            "firewall port 11211 (TCP and UDP), and enable "
                            "SASL if remote clients are truly required."),
        },
    }


RULES = [
    {
        "id": "mongodb-no-auth",
        "title": "MongoDB accepts commands without authentication",
        "severity": "high",
        "confidence": "confirmed",
        "description": "The server answered hello with no credentials.",
        "impact": "Full database compromise; routinely ransomed when exposed.",
        "remediation": "Enable authorization, least-privilege users, bind localhost, firewall 27017.",
        "references": ["https://www.mongodb.com/docs/manual/administration/security-checklist/"],
        "match": _match_mongo_no_auth,
    },
    {
        "id": "mongodb-eol-version",
        "title": "MongoDB version past end-of-life",
        "severity": "medium",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://www.mongodb.com/support-policy/lifecycles"],
        "match": _match_mongo_eol,
    },
    {
        "id": "elasticsearch-no-auth",
        "title": "Elasticsearch answers without authentication",
        "severity": "high",
        "confidence": "confirmed",
        "description": "GET / returned 200 with the cluster banner, no 401.",
        "impact": "Full data compromise; a classic breach source.",
        "remediation": "Enable xpack security, set passwords, use TLS, firewall 9200.",
        "references": ["https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html"],
        "match": _match_es_no_auth,
    },
    {
        "id": "elasticsearch-old-version",
        "title": "Elasticsearch version past end-of-life",
        "severity": "medium",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://www.elastic.co/support/eol"],
        "match": _match_es_old,
    },
    {
        "id": "memcached-exposed",
        "title": "Memcached exposed to the network",
        "severity": "high",
        "confidence": "confirmed",
        "description": "The server answered the version probe; no auth exists by default.",
        "impact": "Cache theft/poisoning; DDoS-amplification abuse.",
        "remediation": "Bind localhost, firewall 11211 TCP+UDP, enable SASL if needed.",
        "references": ["https://memcached.org/"],
        "match": _match_memcached,
    },
]
