"""
Cyber Sentinel AI - Phishing URL feature extraction.
Purely lexical/structural features (no live DNS/WHOIS lookups needed),
so this works fully offline and is deterministic/testable.
"""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking", "confirm",
    "signin", "webscr", "password", "billing", "suspend", "unlock", "wallet",
    "invoice", "alert", "urgent", "recover", "support",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bl.ink", "rebrand.ly", "cutt.ly", "shorte.st",
}

IPV4_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_underscore", "num_slash",
    "num_digits", "num_special_chars", "has_ip_address", "has_at_symbol",
    "has_https", "num_subdomains", "suspicious_keyword_count", "is_shortened",
    "domain_length", "path_length", "num_query_params", "domain_entropy",
    "digit_letter_ratio",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_features(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        parse_target = "http://" + url
    else:
        parse_target = url

    parsed = urlparse(parse_target)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    domain_parts = host.split(".") if host else []
    num_subdomains = max(len(domain_parts) - 2, 0)

    digits = sum(c.isdigit() for c in host)
    letters = sum(c.isalpha() for c in host)

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscore": url.count("_"),
        "num_slash": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(1 for c in url if c in "@%$!#^&*(){}[]|\\~`"),
        "has_ip_address": 1 if IPV4_REGEX.match(host) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "num_subdomains": num_subdomains,
        "suspicious_keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()),
        "is_shortened": 1 if any(host == s or host.endswith("." + s) for s in URL_SHORTENERS) else 0,
        "domain_length": len(host),
        "path_length": len(path),
        "num_query_params": len(query.split("&")) if query else 0,
        "domain_entropy": round(_shannon_entropy(host), 4),
        "digit_letter_ratio": round(digits / letters, 4) if letters else 0.0,
    }
    return features


def features_to_vector(features: dict) -> list:
    return [features[name] for name in FEATURE_NAMES]
