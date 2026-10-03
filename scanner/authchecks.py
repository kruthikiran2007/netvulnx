# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Authenticated checks (Milestone 21).

How credentials are handled — the important part:

* The user may type a username + password on the authorization page when
  they confirm a scan. Those credentials live ONLY in this module's
  in-memory dict, keyed by scan id.
* They are NEVER written to the database, NEVER written to logs, and
  NEVER appear in any finding, ServiceCheck row, or audit event.
* The scan engine takes them out of the vault (single-use pop) when the
  scan starts, uses them, and wipes the reference in a finally block.
* If the server restarts before the scan runs, the dict is gone — the
  scan simply runs without authenticated checks. Fail closed, not open.

What the SSH check does (read-only):

* Opens a normal SSH session with the supplied credentials (paramiko).
  Host keys are auto-accepted — this is a scanner talking to hosts the
  user already authorized, not a long-lived trust relationship.
* Runs ONE command: `sshd -T` (dumps the effective server configuration).
  If that fails (usually: the account lacks permission to read it), the
  check reports that honestly instead of guessing.
* Parses PasswordAuthentication / PermitRootLogin / PermitEmptyPasswords
  / X11Forwarding into a plain dict. The password never leaves this
  function.
"""
import threading

try:
    import paramiko
except ImportError:  # optional dependency; the UI says so honestly
    paramiko = None

from config import Config

TIMEOUT = getattr(Config, "SERVICE_CHECK_TIMEOUT", 5.0)

_vault_lock = threading.Lock()
_vault = {}  # scan_id -> {"username": ..., "password": ...}


def store_credentials(scan_id, username, password):
    """Hold credentials in memory for one upcoming scan. Returns True when
    both parts were non-empty and were stored, False otherwise."""
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        return False
    with _vault_lock:
        _vault[scan_id] = {"username": username, "password": password}
    return True


def take_credentials(scan_id):
    """Single-use pop: the engine calls this once when the scan starts."""
    with _vault_lock:
        return _vault.pop(scan_id, None)


def has_credentials(scan_id):
    with _vault_lock:
        return scan_id in _vault


def parse_sshd_config(text):
    """Parse `sshd -T` output (lines of 'key value') into a dict with
    lower-cased keys. Later lines win, mirroring sshd's own precedence."""
    config = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            config[key] = value
    return config


def check_ssh_config(host, port, username, password, timeout=TIMEOUT):
    """Read the SSH daemon's effective config over an authenticated
    session. Returns {"effective_config": {...}} or {"error": ...}.
    The password is never included in the result."""
    result = {"protocol": "ssh-auth", "port": port, "username": username}
    if paramiko is None:
        result["error"] = ("paramiko is not installed — authenticated SSH "
                           "checks are unavailable")
        return result
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, look_for_keys=False,
                       allow_agent=False)
        try:
            _, stdout, _ = client.exec_command(
                "sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null",
                timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
        finally:
            client.close()
        if exit_code != 0 or not out.strip():
            result["error"] = ("authenticated, but could not read the SSH "
                               "daemon config (sshd -T needs privileges on "
                               "the target)")
            return result
        result["effective_config"] = parse_sshd_config(out)
        result["summary"] = ("read effective sshd config over authenticated "
                             "session")
    except Exception as exc:  # auth failure, timeout, refused — all honest
        result["error"] = f"{type(exc).__name__}: {exc}"
        try:
            client.close()
        except Exception:
            pass
    return result
