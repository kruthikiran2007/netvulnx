# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Rules over the RDP protocol analysis (Milestone 20).

The check (scanner/rdpcheck.py) performs the standard X.224 connection
handshake every RDP client does — no credentials, no session — and reads
which security protocol the server selected:

  rdp-plain-no-tls  (high)   - server selected plain RDP security (no TLS)
  rdp-no-nla        (medium) - server selected TLS but without Network
                               Level Authentication (no CredSSP)

Confidence is "confirmed": the selection comes straight from the
server's own Connection Confirm packet.
"""


def _check(ctx):
    import json
    row = (ctx.get("checks") or {}).get("rdp_negotiate")
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    if d.get("error"):
        return None
    return d


def _match_plain(ctx):
    d = _check(ctx)
    if not d or d.get("selected_protocol") != 0:
        return None
    return {
        "selected_protocol": d.get("selected_protocol"),
        "selected_name": d.get("selected_name"),
        "_finding": {
            "title": "RDP negotiates without TLS",
            "severity": "high",
            "description": (
                "The server selected plain RDP security (no TLS) in the "
                "X.224 handshake. Session traffic — including the login — "
                "is protected only by legacy RDP encryption, and a network "
                "observer can more easily attack the session."),
            "impact": ("Without TLS, RDP sessions are exposed to "
                       "eavesdropping and man-in-the-middle attacks; "
                       "captured sessions can yield credentials."),
            "remediation": ("Set the RDP security layer to 'SSL (TLS 1.2)' "
                            "or 'Negotiate' with NLA required: Windows -> "
                            "Remote Desktop Session Host Configuration / "
                            "Group Policy 'Require use of specific security "
                            "layer for remote connections' = SSL, and "
                            "'Require user authentication for remote "
                            "connections by using Network Level "
                            "Authentication' = Enabled."),
        },
    }


def _match_no_nla(ctx):
    d = _check(ctx)
    if not d or d.get("selected_protocol") != 1:
        return None
    return {
        "selected_protocol": d.get("selected_protocol"),
        "selected_name": d.get("selected_name"),
        "_finding": {
            "title": "RDP uses TLS but Network Level Authentication is off",
            "severity": "medium",
            "description": (
                "The server selected TLS encryption but without CredSSP "
                "Network Level Authentication. The full Windows logon "
                "screen is exposed to unauthenticated clients, which "
                "wastes server resources and widens the pre-auth attack "
                "surface."),
            "impact": ("Pre-authentication RDP vulnerabilities (e.g. "
                       "BlueKeep-class flaws) are reachable without any "
                       "credentials when NLA is off."),
            "remediation": ("Enable Network Level Authentication: Group "
                            "Policy 'Require user authentication for remote "
                            "connections by using Network Level "
                            "Authentication' = Enabled."),
        },
    }


RULES = [
    {
        "id": "rdp-plain-no-tls",
        "title": "RDP negotiates without TLS",  # fallback; refined per finding
        "severity": "high",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/change-listening-port"],
        "match": _match_plain,
    },
    {
        "id": "rdp-no-nla",
        "title": "RDP uses TLS but Network Level Authentication is off",
        "severity": "medium",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/network-level-authentication"],
        "match": _match_no_nla,
    },
]
