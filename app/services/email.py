"""
Cyber Sentinel AI - Email service
Sends verification / password-reset / alert emails via SMTP.
If SMTP is not configured, emails are logged instead of sent (dev mode),
so the rest of the flow (registration, reset) still works end-to-end.
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger("cybersentinel.email")


def _send(to_email: str, subject: str, html_body: str) -> bool:
    if not settings.SMTP_HOST:
        logger.info("[DEV MODE - no SMTP configured] Email to=%s subject=%s\n%s", to_email, subject, html_body)
        return True

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, [to_email], msg.as_string())
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        return False


def send_verification_email(to_email: str, full_name: str, token: str) -> bool:
    subject = "Verify your Cyber Sentinel AI account"
    body = f"""
    <p>Hi {full_name},</p>
    <p>Welcome to Cyber Sentinel AI. Use the verification code below to activate your account:</p>
    <h2>{token}</h2>
    <p>If you did not create this account, you can ignore this email.</p>
    """
    return _send(to_email, subject, body)


def send_password_reset_email(to_email: str, full_name: str, token: str) -> bool:
    subject = "Reset your Cyber Sentinel AI password"
    body = f"""
    <p>Hi {full_name},</p>
    <p>We received a request to reset your password. Use the token below (valid for 30 minutes):</p>
    <h2>{token}</h2>
    <p>If you did not request this, please secure your account immediately.</p>
    """
    return _send(to_email, subject, body)


def send_critical_alert_email(to_email: str, alert_type: str, description: str) -> bool:
    subject = f"[CRITICAL ALERT] {alert_type}"
    body = f"<p><strong>{alert_type}</strong></p><p>{description}</p>"
    return _send(to_email, subject, body)
