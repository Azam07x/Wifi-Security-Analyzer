"""
report_generator.py
--------------------
Exports an assessment to TXT, JSON, or HTML.

Reports never include the raw Wi-Fi password — only the derived
strength label/score, consistent with password_analyzer's privacy
guarantee.
"""

import json
import os
from datetime import datetime


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "reports"
)


def _ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _timestamped_filename(ext):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(
        REPORTS_DIR,
        f"wifi_security_report_{stamp}.{ext}"
    )


def _get_security_rating(score):
    """Return a human-readable rating for the overall security score."""
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Good"
    elif score >= 60:
        return "Fair"
    elif score >= 40:
        return "Weak"
    else:
        return "Critical"


def build_report_data(
    network_info,
    security_info,
    wps_status,
    score_result,
    recommendations,
    password_result=None
):
    """Assemble a single structured dict used by all export formats."""

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),

        "network": {
            "ssid": network_info.get("ssid"),
            "interface": network_info.get("interface"),
            "status": network_info.get("status"),
            "signal_strength": network_info.get("signal_strength"),
            "channel": network_info.get("channel"),
            "frequency": network_info.get("frequency"),
        },

        "security": {
            "type": security_info.get("type"),
            "cipher": security_info.get("cipher"),
            "wps_status": wps_status,
        },

        "password_assessment": (
            {
                "label": password_result.get("label"),
                "score": password_result.get("score")
            }
            if password_result
            else None
        ),

        "security_score": score_result.get("score"),
        "score_breakdown": score_result.get("breakdown"),
        "recommendations": recommendations,
    }


def export_txt(report_data):
    """Export assessment as a TXT report."""

    _ensure_reports_dir()
    path = _timestamped_filename("txt")

    lines = []

    lines.append("Wi-Fi Security Assessment")
    lines.append("=" * 25)
    lines.append(f"Generated: {report_data['generated_at']}")
    lines.append("")

    n = report_data["network"]

    lines.append("NETWORK")
    lines.append("-" * 25)
    lines.append(f"SSID: {n['ssid']}")
    lines.append(f"Interface: {n['interface']}")
    lines.append(f"Status: {n['status']}")
    lines.append(f"Signal Strength: {n['signal_strength']}")
    lines.append(f"Channel: {n['channel']}")
    lines.append(f"Frequency: {n['frequency']}")
    lines.append("")

    s = report_data["security"]

    lines.append("SECURITY")
    lines.append("-" * 25)
    lines.append(f"Security Type: {s['type']}")
    lines.append(f"Cipher: {s['cipher']}")
    lines.append(f"WPS Status: {s['wps_status']}")
    lines.append("")

    if report_data["password_assessment"]:
        pw = report_data["password_assessment"]

        lines.append("PASSWORD STRENGTH")
        lines.append("-" * 25)
        lines.append(f"Password Score: {pw['score']}/100")
        lines.append(f"Password Rating: {pw['label']}")
        lines.append("")
        lines.append(
            "This score measures ONLY the strength "
            "of the Wi-Fi password."
        )
        lines.append("")

    overall_score = report_data["security_score"]
    overall_rating = _get_security_rating(overall_score)

    lines.append("OVERALL WI-FI SECURITY")
    lines.append("-" * 25)
    lines.append(f"Security Score: {overall_score}/100")
    lines.append(f"Security Rating: {overall_rating}")
    lines.append("")
    lines.append(
        "This score evaluates the overall Wi-Fi security "
        "configuration, including security protocol, "
        "encryption, WPS status, and password strength."
    )
    lines.append("")

    lines.append("SCORE BREAKDOWN")
    lines.append("-" * 25)

    for label, points in report_data["score_breakdown"]:
        sign = "+" if points >= 0 else ""
        lines.append(f"{sign}{points}  {label}")

    lines.append("")
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 25)

    for i, rec in enumerate(report_data["recommendations"], 1):
        lines.append(f"{i}. {rec}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return path


def export_json(report_data):
    """Export assessment as JSON."""

    _ensure_reports_dir()
    path = _timestamped_filename("json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    return path


def export_html(report_data):
    """Export assessment as an HTML report."""

    _ensure_reports_dir()
    path = _timestamped_filename("html")

    n = report_data["network"]
    s = report_data["security"]

    overall_score = report_data["security_score"]
    overall_rating = _get_security_rating(overall_score)

    if overall_score >= 80:
        score_color = "#1b8a3e"
    elif overall_score >= 50:
        score_color = "#c98a00"
    else:
        score_color = "#c0392b"

    breakdown_rows = "".join(
        f"""
        <tr>
            <td>{label}</td>
            <td style="text-align:right">
                {'+' if pts >= 0 else ''}{pts}
            </td>
        </tr>
        """
        for label, pts in report_data["score_breakdown"]
    )

    rec_items = "".join(
        f"<li>{r}</li>"
        for r in report_data["recommendations"]
    )

    password_html = ""

    if report_data["password_assessment"]:
        pw = report_data["password_assessment"]

        password_html = f"""
        <section class="password-section">
            <h2>Password Strength</h2>

            <div class="password-score">
                {pw['score']}/100
            </div>

            <p>
                <strong>Password Score:</strong>
                {pw['score']}/100
            </p>

            <p>
                <strong>Password Rating:</strong>
                {pw['label']}
            </p>

            <p class="note">
                This score measures ONLY the strength
                of your Wi-Fi password.
            </p>
        </section>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">

<title>Wi-Fi Security Assessment</title>

<style>

body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                 Arial, sans-serif;

    max-width: 760px;
    margin: 40px auto;
    padding: 0 20px;

    color: #222;
    line-height: 1.5;
}}

h1 {{
    font-size: 24px;
}}

h2 {{
    margin-top: 30px;
    font-size: 19px;
}}

.meta {{
    color: #666;
    font-size: 13px;
}}

.score {{
    font-size: 42px;
    font-weight: bold;
    color: {score_color};
    margin: 5px 0;
}}

.rating {{
    font-size: 18px;
    font-weight: 600;
}}

.password-score {{
    font-size: 30px;
    font-weight: bold;
}}

section {{
    margin-top: 20px;
}}

.note {{
    color: #666;
    font-size: 14px;
}}

.summary {{
    padding: 18px;
    border: 1px solid #ddd;
    border-radius: 8px;
    margin-top: 15px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}}

td {{
    padding: 8px;
    border-bottom: 1px solid #eee;
}}

ul {{
    line-height: 1.7;
}}

</style>

</head>

<body>

<h1>Wi-Fi Security Assessment</h1>

<p class="meta">
Generated: {report_data['generated_at']}
</p>


<h2>Network</h2>

<p>
SSID: {n['ssid']}<br>
Interface: {n['interface']}<br>
Status: {n['status']}<br>
Signal Strength: {n['signal_strength']}<br>
Channel: {n['channel']}<br>
Frequency: {n['frequency']}
</p>


<h2>Security</h2>

<p>
Type: {s['type']}<br>
Cipher: {s['cipher']}<br>
WPS: {s['wps_status']}
</p>


{password_html}


<h2>Overall Wi-Fi Security</h2>

<div class="summary">

    <div class="score">
        {overall_score}/100
    </div>

    <div class="rating">
        Rating: {overall_rating}
    </div>

    <p class="note">
        This is the overall Wi-Fi security score.
        It evaluates the complete security configuration,
        including security protocol, encryption,
        WPS status, and password strength.
    </p>

</div>


<h2>Score Breakdown</h2>

<table>
{breakdown_rows}
</table>


<h2>Recommendations</h2>

<ul>
{rec_items}
</ul>


</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path


EXPORTERS = {
    "txt": export_txt,
    "json": export_json,
    "html": export_html,
}