# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Rules over the SSH algorithm enumeration (Milestone 18).

The check (scanner/sshcheck.py) performs the standard SSH version +
KEXINIT exchange — the same handshake every SSH client does — and records
exactly which algorithms the server advertises. These rules flag the ones
cryptographers consider broken or legacy. Confidence is "confirmed": the
lists come straight from the server's own KEXINIT packet.

Each rule emits ONE finding (via evidence["_finding"]) with severity set
to the worst weak algorithm found, and the weak algorithms enumerated in
the description — cleaner than one finding per algorithm.
"""

# Algorithm -> (severity, why). Only genuinely weak/legacy entries listed;
# anything modern (curve25519, chacha20-poly1305, aes-gcm, sha2-etm) is fine.
WEAK_KEX = {
    "diffie-hellman-group1-sha1": (
        "high", "1024-bit DH — within reach of well-funded attackers"),
    "gss-group1-sha1-": (
        "high", "1024-bit DH with GSSAPI"),
    "diffie-hellman-group14-sha1": (
        "medium", "2048-bit DH but SHA1-based — dated, prefer "
                  "curve25519-sha256"),
    "diffie-hellman-group-exchange-sha1": (
        "medium", "SHA1-based group exchange"),
}

WEAK_HOSTKEY = {
    "ssh-dss": ("high", "1024-bit DSA — deprecated and breakable"),
    "ssh-rsa": ("medium", "SHA1-based signatures — migrate to rsa-sha2-256/512 "
                          "or ssh-ed25519"),
}

WEAK_CIPHER = {
    "3des-cbc": ("high", "64-bit blocks (Sweet32) and slow"),
    "blowfish-cbc": ("high", "64-bit blocks (Sweet32)"),
    "cast128-cbc": ("high", "64-bit blocks (Sweet32)"),
    "arcfour": ("high", "RC4 — broken"),
    "arcfour128": ("high", "RC4 — broken"),
    "arcfour256": ("high", "RC4 — broken"),
    "rijndael-cbc@lysator.liu.se": ("high", "CBC-mode legacy cipher"),
}

WEAK_MAC = {
    "hmac-md5": ("medium", "MD5-based"),
    "hmac-md5-96": ("medium", "MD5-based and truncated"),
    "hmac-sha1-96": ("medium", "truncated to 96 bits"),
    "umac-64-etm@openssh.com": ("low", "64-bit tags — short"),
    "umac-64@openssh.com": ("low", "64-bit tags — short"),
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _check(ctx):
    import json
    row = (ctx.get("checks") or {}).get("ssh_algorithms")
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    if d.get("error"):
        return None
    return d


def _finding(rule_kind, title, found, server_version, impact, remediation):
    """One finding for the whole rule, severity = worst weak algorithm."""
    worst = sorted(found, key=lambda a: _SEV_ORDER[a[1][0]])[0][1][0]
    lines = "\n".join(f"- {a} [{s}]: {why}" for a, (s, why) in
                      sorted(found, key=lambda a: _SEV_ORDER[a[1][0]]))
    return {
        "algorithms": {a: {"severity": s, "why": why}
                       for a, (s, why) in found},
        "server_version": server_version,
        "_finding": {
            "title": title,
            "severity": worst,
            "description": f"{rule_kind} on {server_version or 'the SSH server'}:\n{lines}",
            "impact": impact,
            "remediation": remediation,
        },
    }


def _match_weak_kex(ctx):
    d = _check(ctx)
    if not d:
        return None
    found = []
    for algo in d.get("kex_algorithms", []):
        for weak, info in WEAK_KEX.items():
            if algo == weak or (weak.endswith("-") and algo.startswith(weak)):
                found.append((algo, info))
    if not found:
        return None
    return _finding(
        "Weak key exchange algorithms", "SSH supports weak key exchange",
        found, d.get("server_version"),
        "An attacker able to observe handshakes may recover session keys "
        "negotiated with weak Diffie-Hellman groups.",
        "In sshd_config set 'KexAlgorithms "
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "diffie-hellman-group16-sha512' and restart sshd.")


def _match_weak_hostkey(ctx):
    d = _check(ctx)
    if not d:
        return None
    found = [(a, WEAK_HOSTKEY[a]) for a in d.get("host_key_algorithms", [])
             if a in WEAK_HOSTKEY]
    if not found:
        return None
    return _finding(
        "Weak host key algorithms", "SSH supports weak host key algorithm",
        found, d.get("server_version"),
        "Weak host keys make server-impersonation attacks easier and "
        "undermine the trust model of the SSH connection.",
        "In sshd_config set 'HostKeyAlgorithms "
        "ssh-ed25519,rsa-sha2-256,rsa-sha2-512' and restart sshd.")


def _match_weak_cipher(ctx):
    d = _check(ctx)
    if not d:
        return None
    found = []
    for algo in d.get("ciphers_c2s", []) + d.get("ciphers_s2c", []):
        if algo in WEAK_CIPHER:
            found.append((algo, WEAK_CIPHER[algo]))
        elif algo.endswith("-cbc") and all(a != algo for a, _ in found):
            found.append((algo, ("medium", "CBC mode — padding-oracle class "
                                          "(Lucky13); prefer CTR/GCM/ChaCha20")))
    if not found:
        return None
    return _finding(
        "Weak ciphers", "SSH supports weak cipher",
        found, d.get("server_version"),
        "Broken or CBC-mode ciphers can leak plaintext of the encrypted "
        "session to a network observer.",
        "In sshd_config set 'Ciphers "
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
        "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' "
        "and restart sshd.")


def _match_weak_mac(ctx):
    d = _check(ctx)
    if not d:
        return None
    found = [(a, WEAK_MAC[a])
             for a in d.get("macs_c2s", []) + d.get("macs_s2c", [])
             if a in WEAK_MAC]
    if not found:
        return None
    return _finding(
        "Weak MACs", "SSH supports weak message authentication code",
        found, d.get("server_version"),
        "Weak or truncated MACs weaken integrity protection of the SSH "
        "session against tampering.",
        "In sshd_config set 'MACs "
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
        "hmac-sha2-256,hmac-sha2-512' and restart sshd.")


RULES = [
    {
        "id": "ssh-weak-kex",
        "title": "SSH supports weak key exchange",  # fallback; refined per finding
        "severity": "high",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://www.openssh.com/legacy.html"],
        "match": _match_weak_kex,
    },
    {
        "id": "ssh-weak-hostkey",
        "title": "SSH supports weak host key algorithm",
        "severity": "high",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://www.openssh.com/legacy.html"],
        "match": _match_weak_hostkey,
    },
    {
        "id": "ssh-weak-cipher",
        "title": "SSH supports weak cipher",
        "severity": "high",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://www.openssh.com/legacy.html"],
        "match": _match_weak_cipher,
    },
    {
        "id": "ssh-weak-mac",
        "title": "SSH supports weak message authentication code",
        "severity": "medium",
        "confidence": "confirmed",
        "description": "Fallback — refined per finding by the rule itself.",
        "impact": "Fallback — refined per finding by the rule itself.",
        "remediation": "Fallback — refined per finding by the rule itself.",
        "references": ["https://www.openssh.com/legacy.html"],
        "match": _match_weak_mac,
    },
]
