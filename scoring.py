"""
scoring.py
----------
Combines the security classification and (optional) password strength
into a single transparent 0-100 score, with an itemized breakdown of
every point added or deducted.
"""

from utils import UNKNOWN




def calculate_security_score(security_info, wps_status, password_result=None):
    """
    Calculate a transparent 0-100 Wi-Fi security score.

    Maximum:
    - Security protocol: 70 points
    - WPS: 5 points
    - Password strength: 25 points
    """

    breakdown = []
    score = 0

    sec_type = security_info.get("type", UNKNOWN)
    cipher = security_info.get("cipher", UNKNOWN)

    # --- Security protocol scoring ---
    if sec_type == "WPA3":
        score += 70
        breakdown.append(("WPA3 detected (excellent)", 70))

    elif sec_type == "WPA2/WPA3-Mixed":
        score += 60
        breakdown.append(("WPA2/WPA3 mixed mode (good)", 60))

    elif sec_type == "WPA2":
        if cipher == "TKIP":
            score += 30
            breakdown.append(("WPA2 with legacy TKIP cipher", 30))
        else:
            score += 50
            breakdown.append(("WPA2-AES/CCMP detected (good)", 50))

    elif sec_type == "WPA":
        score += 20
        breakdown.append(("Legacy WPA detected (weak)", 20))

    elif sec_type == "WEP":
        score += 5
        breakdown.append(("WEP detected (severely insecure)", 5))

    elif sec_type == "Open":
        score += 0
        breakdown.append(("Open/unencrypted network (severely insecure)", 0))

    else:
        score += 15
        breakdown.append(("Security type unknown — cannot fully assess", 15))

    # --- Additional cipher penalty ---
    if cipher == "TKIP" and sec_type not in ("WPA2",):
        score -= 10
        breakdown.append(("TKIP cipher in use (legacy, weaker)", -10))

    # --- WPS scoring ---
    if wps_status == "Enabled":
        score -= 10
        breakdown.append(("WPS enabled (increases attack surface)", -10))

    elif wps_status == "Disabled":
        score += 5
        breakdown.append(("WPS disabled (good)", 5))

    else:
        breakdown.append(("WPS status unknown", 0))

    # --- Password strength scoring ---
    if password_result is not None:
        pw_score = password_result.get("score", 0)

        # Password contributes maximum 25 points
        pw_points = round(pw_score * 0.25)

        score += pw_points

        breakdown.append(
            (
                f"Password strength: {password_result.get('label', UNKNOWN)}",
                pw_points
            )
        )

    # --- Keep score between 0 and 100 ---
    final_score = max(0, min(100, score))

    if final_score != score:
        breakdown.append(
            ("Score clamped to valid range (0-100)", final_score - score)
        )

    return {
        "score": final_score,
        "breakdown": breakdown
    }