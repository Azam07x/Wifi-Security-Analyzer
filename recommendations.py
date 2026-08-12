"""
recommendations.py
-------------------
Generates human-readable, defensive security recommendations based on
the detected configuration. Purely advisory — no active remediation
is performed by this tool.
"""

from utils import UNKNOWN


def generate_recommendations(security_info, wps_status, password_result=None):
    recs = []

    sec_type = security_info.get("type", UNKNOWN)
    cipher = security_info.get("cipher", UNKNOWN)

    if sec_type == "Open":
        recs.append("Enable WPA2 or WPA3 encryption immediately — this network is unprotected")
    elif sec_type == "WEP":
        recs.append("Replace WEP with WPA2-AES or WPA3 — WEP is broken and offers no real protection")
    elif sec_type == "WPA":
        recs.append("Upgrade from legacy WPA to WPA2-AES or WPA3")
    elif sec_type == "WPA2":
        recs.append("Consider upgrading to WPA3 if your router and devices support it")
        if cipher == "TKIP":
            recs.append("Switch from TKIP to AES/CCMP cipher in router settings")
    elif sec_type == "WPA2/WPA3-Mixed":
        recs.append("Mixed mode is good for compatibility; move to WPA3-only once all devices support it")
    elif sec_type == "WPA3":
        recs.append("WPA3 is enabled and provides strong wireless security — no protocol upgrade is required")
    else:
        recs.append("Could not determine security type — verify your router's Wi-Fi security settings manually")

    if wps_status == "Enabled":
        recs.append("Disable WPS in your router settings — it is a common attack vector")
    elif wps_status == UNKNOWN:
        recs.append("Check your router's admin panel to confirm WPS status")

    if password_result:
        recs.extend(password_result.get("recommendations", []))

    # General best practices, always included
    recs.append("Keep router firmware updated to patch known vulnerabilities")
    recs.append("Use a long, unique Wi-Fi passphrase not reused from other accounts")
    recs.append("Avoid connecting to or broadcasting open Wi-Fi networks")
    recs.append("Periodically review devices connected to your network")

    # De-duplicate while preserving order
    seen = set()
    unique_recs = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique_recs.append(r)
    return unique_recs
