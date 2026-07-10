"""
Cyber Sentinel AI - Credential Sniffer / Login Activity router.
Detects and reports:
  - DNS queries to known web services (Facebook, Snapchat, etc.)
  - Plaintext HTTP form submissions containing email/password fields
"""
import re
from datetime import datetime
from typing import Optional
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Query
from app.core.deps import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/credentials", tags=["Credentials"])

SERVICES = {
    "facebook": "Facebook", "fb": "Facebook", "fbcdn": "Facebook",
    "snapchat": "Snapchat", "sc-cdn": "Snapchat",
    "instagram": "Instagram", "cdninstagram": "Instagram",
    "twitter": "Twitter / X", "x.com": "Twitter / X", "twimg": "Twitter / X",
    "whatsapp": "WhatsApp", "whatsapp-cdn": "WhatsApp",
    "linkedin": "LinkedIn",
    "tiktok": "TikTok", "tiktokcdn": "TikTok",
    "youtube": "YouTube", "ytimg": "YouTube",
    "google": "Google", "gmail": "Gmail", "mail.google": "Gmail",
    "outlook": "Outlook", "live.com": "Microsoft", "microsoft": "Microsoft",
    "github": "GitHub",
    "reddit": "Reddit",
    "pinterest": "Pinterest",
    "tumblr": "Tumblr",
    "discord": "Discord", "discordapp": "Discord",
    "telegram": "Telegram",
    "netflix": "Netflix",
    "spotify": "Spotify",
    "amazon": "Amazon",
    "dropbox": "Dropbox",
    "zoom": "Zoom",
    "slack": "Slack",
    "medium": "Medium",
    "quora": "Quora",
    "twitch": "Twitch",
    "yahoo": "Yahoo",
}

# Fields we consider "credential-like" in form data
CREDENTIAL_FIELDS = {"email", "password", "passwd", "pass", "login", "username",
                     "user", "user_email", "user_pass", "pwd", "signin", "log",
                     "psswd", "passwort", "contraseña", "motdepasse"}


def detect_service(domain: str) -> Optional[str]:
    domain_lower = domain.lower().rstrip(".")
    for keyword, name in SERVICES.items():
        if keyword in domain_lower:
            return name
    return None


# ---- DNS-based service detection store ----
DETECTED_SERVICES: list[dict] = []


def record_service_access(service: str, domain: str, src_ip: str, timestamp: float, dst_ip: Optional[str] = None):
    DETECTED_SERVICES.append({
        "type": "dns",
        "service": service,
        "domain": domain,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "timestamp": datetime.utcfromtimestamp(timestamp).isoformat(),
    })
    while len(DETECTED_SERVICES) > 500:
        DETECTED_SERVICES.pop(0)


# ---- HTTP plaintext credential extraction store ----
HTTP_CREDENTIALS: list[dict] = []


def record_http_credentials(src_ip: str, dst_ip: str, dst_port: int,
                            method: str, path: str, host: str,
                            form_data: dict[str, str], raw_body: str,
                            timestamp: float):
    HTTP_CREDENTIALS.append({
        "type": "http_credentials",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "method": method,
        "path": path,
        "host": host,
        "form_data": form_data,
        "raw_body": raw_body[:500],
        "timestamp": datetime.utcfromtimestamp(timestamp).isoformat(),
    })
    while len(HTTP_CREDENTIALS) > 500:
        HTTP_CREDENTIALS.pop(0)


def parse_http_form_body(body: str) -> dict[str, str]:
    """Parse URL-encoded form body into a flat dict."""
    try:
        parsed = parse_qs(body, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in parsed.items()}
    except Exception:
        return {}


def extract_credentials_from_form(form_data: dict[str, str]) -> dict[str, str]:
    """Return only the fields that look like credentials."""
    creds = {}
    for k, v in form_data.items():
        kl = k.lower().replace("_", "").replace("-", "")
        if kl in CREDENTIAL_FIELDS or any(f in kl for f in CREDENTIAL_FIELDS):
            creds[k] = v
    return creds


# ---- HTTP raw-payload parser for Scapy ----
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


def parse_http_payload(payload: bytes) -> Optional[dict]:
    """
    Try to parse a raw TCP payload as an HTTP request.
    Returns dict with method, path, host, body or None.
    """
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None

    # Check if it starts with an HTTP method
    first_line_end = text.find("\r\n")
    if first_line_end == -1:
        return None
    first_line = text[:first_line_end]
    parts = first_line.split(" ")
    if len(parts) < 2 or parts[0] not in HTTP_METHODS:
        return None

    method = parts[0]
    path = parts[1]
    host = ""
    body = ""

    # Parse headers
    header_end = text.find("\r\n\r\n")
    if header_end != -1:
        headers_text = text[:header_end]
        for line in headers_text.split("\r\n")[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
        body = text[header_end + 4:]

    return {
        "method": method,
        "path": path,
        "host": host,
        "body": body,
    }


@router.get("/detections")
def get_detections(
    service: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_active_user),
):
    results = DETECTED_SERVICES
    if service:
        results = [r for r in results if r["service"].lower() == service.lower()]
    return {"total": len(results), "detections": results[-limit:][::-1]}


@router.get("/http-credentials")
def get_http_credentials(
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_active_user),
):
    return {
        "total": len(HTTP_CREDENTIALS),
        "credentials": HTTP_CREDENTIALS[-limit:][::-1],
    }
