"""
password_analyzer.py
---------------------
Local password/passphrase strength assessment.

IMPORTANT PRIVACY GUARANTEE:
The password text is only ever held in a local Python variable for the
duration of this function call. It is never written to disk, never
logged, never included in generated reports, and never transmitted
anywhere. Only the resulting score/label/recommendations are returned.
"""

import re

COMMON_PASSWORDS = {
    "password", "12345678", "123456789", "qwerty123", "letmein",
    "admin123", "welcome1", "iloveyou", "football", "password1",
    "abc12345", "monkey123", "dragon123", "sunshine1", "princess1",
}

SEQUENTIAL_PATTERNS = [
    "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop",
]


def analyze_password_strength(password):
    """
    Return a dict:
      {
        "score": int 0-100,
        "label": "Very Weak"|"Weak"|"Fair"|"Strong"|"Very Strong",
        "checks": {...booleans...},
        "recommendations": [str, ...]
      }
    The raw password itself is NOT included in the return value.
    """
    if password is None:
        password = ""

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))
    is_common = password.lower() in COMMON_PASSWORDS
    has_sequential = _has_sequential_pattern(password)
    has_repeated = _has_repeated_pattern(password)

    score = 0
    recommendations = []

    # Length scoring (biggest factor)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 15
        recommendations.append("Use at least 14-16 characters for stronger protection")
    else:
        recommendations.append("Password is too short — use at least 14-16 characters")

    # Character variety
    variety = sum([has_upper, has_lower, has_digit, has_special])
    score += variety * 10
    if not has_upper:
        recommendations.append("Add uppercase letters")
    if not has_lower:
        recommendations.append("Add lowercase letters")
    if not has_digit:
        recommendations.append("Add numbers")
    if not has_special:
        recommendations.append("Add special characters (e.g. !, #, %, *)")

    # Penalties
    if is_common:
        score -= 40
        recommendations.append("Avoid common or well-known passwords")
    if has_sequential:
        score -= 15
        recommendations.append("Avoid sequential patterns (e.g. abcd, 1234)")
    if has_repeated:
        score -= 15
        recommendations.append("Avoid repeated character patterns (e.g. aaaa, 1212)")

    score = max(0, min(100, score))

    if score < 20:
        label = "Very Weak"
    elif score < 40:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    if not recommendations:
        recommendations.append("Good password hygiene — consider a passphrase for even more entropy")

    return {
        "score": score,
        "label": label,
        "checks": {
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
            "is_common_password": is_common,
            "has_sequential_pattern": has_sequential,
            "has_repeated_pattern": has_repeated,
        },
        "recommendations": recommendations,
    }


def _has_sequential_pattern(password, min_run=4):
    lowered = password.lower()
    for pattern in SEQUENTIAL_PATTERNS:
        for i in range(len(pattern) - min_run + 1):
            chunk = pattern[i:i + min_run]
            if chunk in lowered:
                return True
            if chunk[::-1] in lowered:
                return True
    return False


def _has_repeated_pattern(password, min_run=4):
    if not password:
        return False
    run_char = password[0]
    run_len = 1
    for ch in password[1:]:
        if ch == run_char:
            run_len += 1
            if run_len >= min_run:
                return True
        else:
            run_char = ch
            run_len = 1
    return False
