"""Outgoing email (Milestone 20).

Currently used for password-reset links. Sending is deliberately simple
(smtplib + STARTTLS) and honest: if SMTP isn't configured, the caller
gets ``(False, reason)`` and the UI says the feature is unavailable —
it never pretends an email went out.

Settings come from the Flask app config (see config.py: NETVULNX_SMTP_*
environment variables), so tests can override them per-app.
"""
import logging
import smtplib
from email.message import EmailMessage

from flask import current_app

log = logging.getLogger(__name__)


def smtp_configured() -> bool:
    return bool(current_app.config.get("SMTP_ENABLED"))


def send_email(to: str, subject: str, body: str):
    """Send a plain-text email. Returns (ok, error_message)."""
    cfg = current_app.config
    if not smtp_configured():
        return False, "Email is not configured on this server."
    msg = EmailMessage()
    msg["From"] = cfg.get("SMTP_FROM")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg.get("SMTP_HOST"), cfg.get("SMTP_PORT"),
                          timeout=15) as smtp:
            if cfg.get("SMTP_USE_TLS"):
                smtp.starttls()
            if cfg.get("SMTP_USERNAME"):
                smtp.login(cfg.get("SMTP_USERNAME"),
                           cfg.get("SMTP_PASSWORD"))
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        log.warning("email send failed: %s", exc)
        return False, f"Could not send email: {exc}"
    return True, ""


def send_password_reset(to: str, username: str, reset_url: str):
    """Email a password-reset link. Returns (ok, error_message)."""
    body = (
        f"Hello {username},\n\n"
        "Someone requested a password reset for your NetVulnX account.\n"
        "If that was you, click the link below (valid for 1 hour, "
        "single use):\n\n"
        f"{reset_url}\n\n"
        "If you didn't ask for this, just ignore this email — your "
        "password stays unchanged.\n\n"
        "— NetVulnX\n"
    )
    return send_email(to, "NetVulnX password reset", body)
