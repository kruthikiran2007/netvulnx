"""Tests for authenticated checks (Milestone 21).

* The credential vault: store/take/has semantics, single-use pop.
* sshd -T parsing.
* Rule matching against fabricated check rows.
* End-to-end SSH audit against a REAL paramiko SSH server running on
  localhost (skipped when paramiko is not installed) — the test exercises
  the actual SSH wire protocol, not a mock of the client.
"""
import json
import socket
import threading
from types import SimpleNamespace

import pytest

from scanner import authchecks
from rules import sshaudit_rules

try:
    import paramiko as _paramiko
    _HAS_PARAMIKO = True
except ImportError:
    _paramiko = None
    _HAS_PARAMIKO = False

needs_paramiko = pytest.mark.skipif(not _HAS_PARAMIKO,
                                    reason="paramiko not installed")

SSHD_T = """\
port 22
passwordauthentication yes
permitrootlogin yes
permitemptypasswords no
x11forwarding no
maxauthtries 6
"""


# --------------------------------------------------------------------------
# Vault semantics
# --------------------------------------------------------------------------
def test_vault_store_and_take():
    assert authchecks.store_credentials(424201, "ops", "s3cret")
    assert authchecks.has_credentials(424201)
    creds = authchecks.take_credentials(424201)
    assert creds == {"username": "ops", "password": "s3cret"}
    # Single-use: second take finds nothing.
    assert authchecks.take_credentials(424201) is None
    assert not authchecks.has_credentials(424201)


def test_vault_rejects_empty():
    assert not authchecks.store_credentials(424202, "", "s3cret")
    assert not authchecks.store_credentials(424202, "ops", "")
    assert not authchecks.has_credentials(424202)


# --------------------------------------------------------------------------
# sshd -T parsing
# --------------------------------------------------------------------------
def test_parse_sshd_config():
    cfg = authchecks.parse_sshd_config(SSHD_T)
    assert cfg["passwordauthentication"] == "yes"
    assert cfg["permitrootlogin"] == "yes"
    assert cfg["permitemptypasswords"] == "no"
    assert cfg["maxauthtries"] == "6"


def test_parse_sshd_config_ignores_comments():
    cfg = authchecks.parse_sshd_config("# comment\n\nport 22\n")
    assert cfg == {"port": "22"}


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def _ctx(config):
    row = SimpleNamespace(details=json.dumps({"effective_config": config}))
    return {"checks": {"ssh_config_audit": row}}


def test_rule_empty_passwords_critical():
    ev = sshaudit_rules._match_empty_passwords(
        _ctx({"permitemptypasswords": "yes"}))
    assert ev["_finding"]["severity"] == "critical"
    assert sshaudit_rules._match_empty_passwords(
        _ctx({"permitemptypasswords": "no"})) is None


def test_rule_root_login_high():
    ev = sshaudit_rules._match_root_login(_ctx({"permitrootlogin": "yes"}))
    assert ev["_finding"]["severity"] == "high"
    # prohibit-password (key-only root) is fine — no finding.
    assert sshaudit_rules._match_root_login(
        _ctx({"permitrootlogin": "prohibit-password"})) is None


def test_rule_password_auth_medium():
    ev = sshaudit_rules._match_password_auth(
        _ctx({"passwordauthentication": "yes"}))
    assert ev["_finding"]["severity"] == "medium"
    assert sshaudit_rules._match_password_auth(
        _ctx({"passwordauthentication": "no"})) is None


def test_rule_x11_low():
    ev = sshaudit_rules._match_x11(_ctx({"x11forwarding": "yes"}))
    assert ev["_finding"]["severity"] == "low"


def test_rules_ignore_errors():
    row = SimpleNamespace(details=json.dumps({"error": "auth failed"}))
    ctx = {"checks": {"ssh_config_audit": row}}
    assert sshaudit_rules._match_root_login(ctx) is None


# --------------------------------------------------------------------------
# Fake SSH server (real paramiko wire protocol) — defined only when
# paramiko exists; the end-to-end tests skip otherwise.
# --------------------------------------------------------------------------
if _HAS_PARAMIKO:
    class _FakeSSHServer(_paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return _paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return _paramiko.OPEN_SUCCEEDED

        def check_channel_exec_request(self, channel, command):
            self.command = command
            return True

    def _run_fake_ssh():
        host_key = _paramiko.RSAKey.generate(2048)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def run():
            conn, _ = srv.accept()
            transport = _paramiko.Transport(conn)
            transport.add_server_key(host_key)
            server = _FakeSSHServer()
            transport.start_server(server=server)
            chan = transport.accept(10)
            if chan is None:
                return
            for _ in range(100):
                if hasattr(server, "command"):
                    break
                threading.Event().wait(0.05)
            if b"sshd -T" in server.command:
                chan.send(SSHD_T.encode())
                chan.send_exit_status(0)
            else:
                chan.send_exit_status(127)
            chan.close()
            transport.close()
            srv.close()

        threading.Thread(target=run, daemon=True).start()
        return port


@needs_paramiko
def test_ssh_config_audit_end_to_end():
    port = _run_fake_ssh()
    res = authchecks.check_ssh_config("127.0.0.1", port, "tester",
                                      "hunter2", timeout=10)
    assert "error" not in res, res.get("error")
    cfg = res["effective_config"]
    assert cfg["permitrootlogin"] == "yes"
    # The password must never appear in the result dict.
    assert "hunter2" not in json.dumps(res)


@needs_paramiko
def test_ssh_config_audit_bad_auth():
    # No server here at all -> honest error, no crash.
    res = authchecks.check_ssh_config("127.0.0.1", 1, "u", "p", timeout=3)
    assert "error" in res
