"""
Cyber Sentinel AI - Password strength analyzer.
Deterministic analysis: length, character-set entropy, common-password
dictionary check, pattern detection (sequential/keyboard/repeated chars),
estimated offline crack time, and actionable recommendations.
"""
import math
import re

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "password1", "111111", "123123", "iloveyou", "admin", "welcome", "monkey",
    "login", "letmein", "dragon", "master", "sunshine", "princess", "football",
    "1234567", "123321", "qwertyuiop", "000000", "1q2w3e4r", "qazwsx", "trustno1",
    "superman", "batman", "shadow", "michael", "jennifer", "hunter", "hello123",
    "passw0rd", "p@ssw0rd", "admin123", "root", "toor", "changeme", "default",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

SEQUENTIAL_PATTERN = re.compile(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg)", re.IGNORECASE)
REPEATED_CHAR_PATTERN = re.compile(r"(.)\1{2,}")  # same char 3+ times in a row


def _charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size or 1


def _entropy_bits(password: str) -> float:
    charset = _charset_size(password)
    return len(password) * math.log2(charset)


def _has_keyboard_pattern(password: str) -> bool:
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            if row[i:i + 4] in lower or row[i:i + 4][::-1] in lower:
                return True
    return False


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("centuries", 100 * 365.25 * 24 * 3600),
        ("years", 365.25 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if name == "centuries" and value > 1e6:
                return f"{value:.2e} centuries (effectively uncrackable)"
            if value > 1000 and name != "centuries":
                continue
            return f"{value:,.1f} {name}"
    return "instantly"


def analyze_password(password: str) -> dict:
    length = len(password)
    entropy_bits = _entropy_bits(password)

    is_common = password.lower() in COMMON_PASSWORDS
    has_sequential = bool(SEQUENTIAL_PATTERN.search(password))
    has_repeated = bool(REPEATED_CHAR_PATTERN.search(password))
    has_keyboard_pattern = _has_keyboard_pattern(password)

    # Offline attack rate assumption: 10 billion guesses/sec (modern GPU rig against unsalted/fast hash)
    guesses_per_second = 1e10
    avg_guesses = (2 ** entropy_bits) / 2
    crack_seconds = avg_guesses / guesses_per_second if not is_common else 0.001

    if is_common or entropy_bits < 28:
        strength = "very weak"
    elif entropy_bits < 40:
        strength = "weak"
    elif entropy_bits < 60:
        strength = "moderate"
    elif entropy_bits < 80:
        strength = "strong"
    else:
        strength = "very strong"

    recommendations = []
    if length < 12:
        recommendations.append("Use at least 12 characters — longer passwords are exponentially harder to crack")
    if not any(c.isupper() for c in password):
        recommendations.append("Add uppercase letters")
    if not any(c.islower() for c in password):
        recommendations.append("Add lowercase letters")
    if not any(c.isdigit() for c in password):
        recommendations.append("Add numbers")
    if not any(not c.isalnum() for c in password):
        recommendations.append("Add special characters (e.g. !@#$%^&*)")
    if is_common:
        recommendations.append("This is one of the most commonly breached passwords — never use it")
    if has_sequential:
        recommendations.append("Avoid sequential characters like '1234' or 'abcd'")
    if has_repeated:
        recommendations.append("Avoid repeating the same character multiple times in a row")
    if has_keyboard_pattern:
        recommendations.append("Avoid keyboard-adjacent patterns like 'qwerty' or 'asdf'")
    if not recommendations:
        recommendations.append("This password meets all basic strength criteria. Consider a passphrase for even better memorability.")

    return {
        "length": length,
        "entropy_bits": round(entropy_bits, 2),
        "strength": strength,
        "is_common_password": is_common,
        "has_sequential_pattern": has_sequential,
        "has_repeated_characters": has_repeated,
        "has_keyboard_pattern": has_keyboard_pattern,
        "estimated_crack_time": _format_duration(crack_seconds),
        "recommendations": recommendations,
    }
