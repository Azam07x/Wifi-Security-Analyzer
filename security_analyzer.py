"""
security_analyzer.py
---------------------
Classifies the Wi-Fi security configuration reported by scanner.py.

Pure text classification — no active testing, no probing, no
brute-force logic. It only interprets strings the OS already gave us.
"""

from utils import UNKNOWN


def classify_security(security_raw, encryption_raw):
    """
    Return a dict:
      {
        "type": "Open" | "WEP" | "WPA" | "WPA2" | "WPA3" |
                "WPA2/WPA3-Mixed" | UNKNOWN,
        "cipher": "TKIP" | "AES/CCMP" | "SAE" | UNKNOWN,
        "risk_level": "critical" | "high" | "medium" | "low" | "none" | UNKNOWN
      }
    """
    sec_text = (security_raw or "").upper()
    enc_text = (encryption_raw or "").upper()

    if security_raw in (None, "", UNKNOWN) and encryption_raw in (None, "", UNKNOWN):
        return {"type": UNKNOWN, "cipher": UNKNOWN, "risk_level": UNKNOWN}

    combined = f"{sec_text} {enc_text}"

    if "OPEN" in combined or combined.strip() == "NONE":
        sec_type = "Open"
        risk = "critical"
    elif "WEP" in combined:
        sec_type = "WEP"
        risk = "critical"
    elif "WPA3" in combined and "WPA2" in combined:
        sec_type = "WPA2/WPA3-Mixed"
        risk = "low"
    elif "WPA3" in combined:
        sec_type = "WPA3"
        risk = "none"
    elif "WPA2" in combined:
        sec_type = "WPA2"
        risk = "low"
    elif "WPA" in combined:
        sec_type = "WPA"
        risk = "high"
    else:
        sec_type = UNKNOWN
        risk = UNKNOWN

    if "TKIP" in combined:
        cipher = "TKIP"
    elif "CCMP" in combined or "AES" in combined:
        cipher = "AES/CCMP"
    elif "SAE" in combined or "GCMP" in combined:
        cipher = "SAE/GCMP"
    else:
        cipher = UNKNOWN

    return {"type": sec_type, "cipher": cipher, "risk_level": risk}


def classify_wps(wps_raw):
    """Normalize WPS status text. Never guesses if unavailable."""
    if not wps_raw or wps_raw == UNKNOWN:
        return UNKNOWN
    text = wps_raw.strip().lower()
    if "enable" in text or text in ("yes", "on"):
        return "Enabled"
    if "disable" in text or text in ("no", "off"):
        return "Disabled"
    return UNKNOWN
