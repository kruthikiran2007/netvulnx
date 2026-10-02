"""Rules over the authenticated SSH config audit (Milestone 21).

The check (scanner/authchecks.py) logs in with user-supplied credentials
(held in memory only, never stored) and reads `sshd -T` — the daemon's
own effective configuration. These rules flag the dangerous settings:

  ssh-auth-empty-passwords      (critical) - anyone can log in with no password
  ssh-auth-root-login           (high)     - remote root login permitted
  ssh-auth-password-enabled     (medium)   - password auth on (brute-forceable)
  ssh-auth-x11-forwarding       (low)      - X11 forwarding enabled
"""
import json


def _config(ctx):
    row = (ctx.get("checks") or {}).get("ssh_config_audit")
    if row is None:
        return None
    try:
        d = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        return None
    if d.get("error"):
        return None
    return d.get("effective_config") or {}


def _is_yes(cfg, key):
    return cfg.get(key, "").strip().lower() in ("yes", "true", "1")


def _match_empty_passwords(ctx):
    cfg = _config(ctx)
    if cfg is None or not _is_yes(cfg, "permitemptypasswords"):
        return None
    return {
        "_finding": {
            "title": "SSH permits empty passwords",
            "severity": "critical",
            "description": ("The SSH daemon's effective configuration "
                            "(PermitEmptyPasswords yes, read via sshd -T) "
                            "allows accounts to authenticate with no "
                            "password at all."),
            "impact": ("Anyone who can reach port 22 can log in as any "
                       "account with an empty password — trivial, fully "
                       "remote compromise."),
            "remediation": ("Set 'PermitEmptyPasswords no' in sshd_config, "
                            "restart sshd, and audit accounts for empty "
                            "password fields."),
        },
    }


def _match_root_login(ctx):
    cfg = _config(ctx)
    if cfg is None:
        return None
    if cfg.get("permitrootlogin", "").strip().lower() != "yes":
        return None
    return {
        "_finding": {
            "title": "SSH permits remote root login",
            "severity": "high",
            "description": ("The SSH daemon's effective configuration "
                            "(PermitRootLogin yes) allows direct remote "
                            "login as root."),
            "impact": ("Password-guessing attacks target the most powerful "
                       "account directly; a single guessed password is full "
                       "host compromise with no privilege-escalation step."),
            "remediation": ("Set 'PermitRootLogin no' (or "
                            "'prohibit-password' if key-only root access is "
                            "truly required) in sshd_config and restart sshd."),
        },
    }


def _match_password_auth(ctx):
    cfg = _config(ctx)
    if cfg is None or not _is_yes(cfg, "passwordauthentication"):
        return None
    return {
        "_finding": {
            "title": "SSH password authentication enabled",
            "severity": "medium",
            "description": ("The SSH daemon accepts password authentication "
                            "(PasswordAuthentication yes), which is "
                            "susceptible to brute-force and credential-"
                            "stuffing attacks."),
            "impact": ("Attackers can hammer the login prompt with stolen "
                       "or guessed passwords; weak user passwords become "
                       "remote access."),
            "remediation": ("Prefer key-only auth: set "
                            "'PasswordAuthentication no' in sshd_config "
                            "(after confirming key access works), restart "
                            "sshd, and consider fail2ban for the remaining "
                            "exposure."),
        },
    }


def _match_x11(ctx):
    cfg = _config(ctx)
    if cfg is None or not _is_yes(cfg, "x11forwarding"):
        return None
    return {
        "_finding": {
            "title": "SSH X11 forwarding enabled",
            "severity": "low",
            "description": ("X11Forwarding is enabled. It widens the attack "
                            "surface of every SSH session slightly and is "
                            "rarely needed on servers."),
            "impact": ("Minor: potential X11-based session hijacking if an "
                       "attacker already has a foothold as the SSH user."),
            "remediation": ("Set 'X11Forwarding no' in sshd_config and "
                            "restart sshd unless graphical forwarding is "
                            "genuinely used."),
        },
    }


RULES = [
    {
        "id": "ssh-auth-empty-passwords",
        "title": "SSH permits empty passwords",
        "severity": "critical",
        "confidence": "confirmed",
        "description": "PermitEmptyPasswords is yes in the effective sshd config.",
        "impact": "Remote login with no password — trivial full compromise.",
        "remediation": "Set 'PermitEmptyPasswords no' and restart sshd.",
        "references": ["https://www.ssh.com/academy/ssh/sshd_config"],
        "match": _match_empty_passwords,
    },
    {
        "id": "ssh-auth-root-login",
        "title": "SSH permits remote root login",
        "severity": "high",
        "confidence": "confirmed",
        "description": "PermitRootLogin is yes in the effective sshd config.",
        "impact": "Direct brute-force target on the most powerful account.",
        "remediation": "Set 'PermitRootLogin no' and restart sshd.",
        "references": ["https://www.ssh.com/academy/ssh/sshd_config"],
        "match": _match_root_login,
    },
    {
        "id": "ssh-auth-password-enabled",
        "title": "SSH password authentication enabled",
        "severity": "medium",
        "confidence": "confirmed",
        "description": "PasswordAuthentication is yes in the effective sshd config.",
        "impact": "Brute-force / credential-stuffing exposure.",
        "remediation": "Move to key-only auth; set 'PasswordAuthentication no'.",
        "references": ["https://www.ssh.com/academy/ssh/sshd_config"],
        "match": _match_password_auth,
    },
    {
        "id": "ssh-auth-x11-forwarding",
        "title": "SSH X11 forwarding enabled",
        "severity": "low",
        "confidence": "confirmed",
        "description": "X11Forwarding is yes in the effective sshd config.",
        "impact": "Minor session-hijack surface; rarely needed on servers.",
        "remediation": "Set 'X11Forwarding no' and restart sshd.",
        "references": ["https://www.ssh.com/academy/ssh/sshd_config"],
        "match": _match_x11,
    },
]
