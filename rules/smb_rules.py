"""Rules over the SMB protocol analysis (Milestone 20).

The check (scanner/smbcheck.py) performs the standard SMB2 + SMB1
negotiate handshakes — the same hellos every SMB client sends — without
authenticating. These rules flag:

  smb-v1-enabled          (high)   - the deprecated SMBv1 dialect is still
                                    accepted (WannaCry / EternalBlue vector)
  smb-signing-not-required(medium) - the server does not require message
                                    signing -> NTLM relay attacks possible

Confidence is "confirmed": both facts come straight from the server's
own negotiate responses.
"""


def _check(ctx):
    import json
    row = (ctx.get("checks") or {}).get("smb_negotiate")
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    if d.get("error"):
        return None
    return d


def _match_smbv1(ctx):
    d = _check(ctx)
    if not d or not d.get("smbv1_enabled"):
        return None
    return {
        "smbv1_enabled": True,
        "negotiated_dialect": d.get("dialect_name"),
        "_finding": {
            "title": "SMBv1 dialect still enabled",
            "severity": "high",
            "description": (
                "The server accepted our SMB1 (NT LM 0.12) negotiate "
                "request, so the deprecated SMBv1 dialect is enabled. "
                f"It also negotiates {d.get('dialect_name') or 'a newer dialect'} "
                "for modern clients, but any client — or worm — may still "
                "use SMBv1."),
            "impact": ("SMBv1 has unfixable design flaws and was the "
                       "propagation vector for WannaCry/EternalBlue. Leaving "
                       "it enabled exposes the host to network worms and "
                       "downgrade attacks."),
            "remediation": ("Disable SMBv1 on the server. Windows: "
                            "'Disable-WindowsOptionalFeature -Online "
                            "-FeatureName SMB1Protocol' and set the "
                            "registry 'SMB1' DWORD to 0, then reboot. "
                            "Samba: set 'server min protocol = SMB2' in "
                            "smb.conf."),
        },
    }


def _match_signing(ctx):
    d = _check(ctx)
    if not d or d.get("signing_required"):
        return None
    detail = ("signing disabled entirely" if not d.get("signing_enabled")
              else "signing offered but not required")
    return {
        "signing_enabled": d.get("signing_enabled"),
        "signing_required": False,
        "_finding": {
            "title": "SMB signing not required",
            "severity": "medium",
            "description": (
                f"The server's negotiate response shows {detail}. An "
                "attacker in a man-in-the-middle position can relay "
                "authentication attempts to this server."),
            "impact": ("Without mandatory signing, NTLM relay attacks can "
                       "hijack authenticated SMB sessions and gain the "
                       "victim's access on this host."),
            "remediation": ("Require signing. Windows: Group Policy "
                            "'Microsoft network server: Digitally sign "
                            "communications (always)' -> Enabled. Samba: "
                            "set 'server signing = mandatory' in smb.conf."),
        },
    }


RULES = [
    {
        "id": "smb-v1-enabled",
        "title": "SMBv1 dialect still enabled",  # fallback; refined per finding
        "severity": "high",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
        "match": _match_smbv1,
    },
    {
        "id": "smb-signing-not-required",
        "title": "SMB signing not required",  # fallback; refined per finding
        "severity": "medium",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-relay-attacks"],
        "match": _match_signing,
    },
]
