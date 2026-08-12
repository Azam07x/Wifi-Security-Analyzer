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

    # --- Presentation-only helpers (no scoring/business logic here) ---

    def _score_color(score):
        """Map a 0-100 score to a status color. Display logic only."""
        if score >= 80:
            return "#2ecc71"   # good / positive
        elif score >= 50:
            return "#f1c40f"   # warning / medium
        else:
            return "#e74c3c"   # danger / low

    def _score_class(score):
        if score >= 80:
            return "good"
        elif score >= 50:
            return "warn"
        else:
            return "bad"

    def _wps_badge_class(wps_value):
        """
        Choose a visual badge style for the WPS status text.
        This never alters or invents the underlying value -
        it only decides how the *existing* text is colored.
        """
        text = str(wps_value).strip().lower()

        if any(k in text for k in ("enabled", "vulnerable", "active", "on")):
            return "bad"
        if any(k in text for k in ("disabled", "off", "not detected", "not present")):
            return "good"
        if any(k in text for k in ("unknown", "not available", "n/a", "unsupported")):
            return "unknown"
        return "unknown"

    overall_color = _score_color(overall_score)
    overall_class = _score_class(overall_score)
    wps_class = _wps_badge_class(s.get("wps_status"))

    # Overall score ring (conic-gradient donut, pure CSS, no JS/images)
    overall_ring_style = (
        f"background: conic-gradient({overall_color} "
        f"{overall_score * 3.6}deg, rgba(255,255,255,0.08) 0deg);"
    )

    breakdown_rows = "".join(
        f"""
        <div class="breakdown-row">
            <span class="breakdown-label">{label}</span>
            <span class="breakdown-points {'pts-pos' if pts >= 0 else 'pts-neg'}">
                {'+' if pts >= 0 else ''}{pts}
            </span>
        </div>
        """
        for label, pts in report_data["score_breakdown"]
    )

    rec_items = "".join(
        f"""
        <li class="rec-card">
            <span class="rec-index">{i}</span>
            <span class="rec-text">{r}</span>
        </li>
        """
        for i, r in enumerate(report_data["recommendations"], 1)
    )

    password_html = ""

    if report_data["password_assessment"]:
        pw = report_data["password_assessment"]
        pw_score = pw["score"]
        pw_color = _score_color(pw_score)
        pw_class = _score_class(pw_score)
        pw_ring_style = (
            f"background: conic-gradient({pw_color} "
            f"{pw_score * 3.6}deg, rgba(255,255,255,0.08) 0deg);"
        )

        password_html = f"""
            <div class="score-card">
                <div class="score-card-label">
                    <svg class="icon" viewBox="0 0 24 24" fill="none">
                        <path d="M12 17a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z" stroke="currentColor" stroke-width="1.6"/>
                        <path d="M6 10V7a6 6 0 1 1 12 0v3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
                        <rect x="4" y="10" width="16" height="11" rx="2.2" stroke="currentColor" stroke-width="1.6"/>
                    </svg>
                    Password Strength Score
                </div>
                <div class="ring {pw_class}" style="{pw_ring_style}">
                    <div class="ring-inner">
                        <span class="ring-score">{pw_score}</span>
                        <span class="ring-max">/100</span>
                    </div>
                </div>
                <div class="badge {pw_class}">{pw['label']}</div>
                <p class="card-note">
                    Measures ONLY the strength of the Wi-Fi password.
                </p>
            </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wi-Fi Security Assessment Report</title>
<style>

:root {{
    --bg: #0b0f14;
    --bg-alt: #10161d;
    --panel: #131a22;
    --panel-border: #223140;
    --text: #e6edf3;
    --text-dim: #8aa0b3;
    --text-faint: #5c7387;
    --accent: #38bdf8;
    --accent-dim: #1e6f8f;
    --good: #2ecc71;
    --warn: #f1c40f;
    --bad: #e74c3c;
    --unknown: #8aa0b3;
    --radius: 12px;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    background:
        radial-gradient(circle at 15% 0%, rgba(56,189,248,0.08), transparent 45%),
        radial-gradient(circle at 85% 15%, rgba(46,204,113,0.06), transparent 40%),
        var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                 Roboto, Arial, sans-serif;
    line-height: 1.55;
}}

.wrap {{
    max-width: 1040px;
    margin: 0 auto;
    padding: 28px 22px 60px;
}}

/* ---------- Header ---------- */

.header {{
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 24px 26px;
    background: linear-gradient(135deg, #101923, #0c131a);
    border: 1px solid var(--panel-border);
    border-radius: var(--radius);
    margin-bottom: 26px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.35);
}}

.header-icon {{
    flex: 0 0 auto;
    width: 52px;
    height: 52px;
    border-radius: 50%;
    background: rgba(56,189,248,0.12);
    border: 1px solid rgba(56,189,248,0.35);
    display: flex;
    align-items: center;
    justify-content: center;
}}

.header-icon svg {{
    width: 26px;
    height: 26px;
    color: var(--accent);
}}

.header-text h1 {{
    margin: 0 0 2px;
    font-size: 21px;
    letter-spacing: 0.2px;
}}

.header-text .subtitle {{
    margin: 0 0 8px;
    color: var(--text-dim);
    font-size: 13.5px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
}}

.header-text .meta {{
    margin: 0;
    color: var(--text-faint);
    font-size: 12.5px;
}}

/* ---------- Sections ---------- */

.section {{
    margin-top: 30px;
}}

.section-title {{
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: var(--text-dim);
    margin-bottom: 12px;
}}

.section-title::before {{
    content: "";
    width: 4px;
    height: 14px;
    background: var(--accent);
    border-radius: 2px;
    display: inline-block;
}}

/* ---------- Score cards ---------- */

.score-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 16px;
}}

.score-card {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: var(--radius);
    padding: 20px;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    box-shadow: 0 4px 14px rgba(0,0,0,0.25);
}}

.score-card.primary {{
    border-color: rgba(56,189,248,0.35);
    background: linear-gradient(180deg, rgba(56,189,248,0.06), var(--panel));
}}

.score-card-label {{
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-dim);
    margin-bottom: 14px;
}}

.icon {{
    width: 15px;
    height: 15px;
    color: var(--accent);
    flex: 0 0 auto;
}}

/* Circular ring using conic-gradient, pure CSS */
.ring {{
    width: 128px;
    height: 128px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 12px;
}}

.ring-inner {{
    width: 100px;
    height: 100px;
    border-radius: 50%;
    background: var(--panel);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}}

.ring-score {{
    font-size: 27px;
    font-weight: 800;
}}

.ring-max {{
    font-size: 11px;
    color: var(--text-faint);
    margin-top: -2px;
}}

.badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 12.5px;
    font-weight: 700;
    letter-spacing: 0.4px;
    border: 1px solid transparent;
}}

.badge.good {{ color: var(--good); background: rgba(46,204,113,0.12); border-color: rgba(46,204,113,0.35); }}
.badge.warn {{ color: var(--warn); background: rgba(241,196,15,0.12); border-color: rgba(241,196,15,0.35); }}
.badge.bad  {{ color: var(--bad);  background: rgba(231,76,60,0.12);  border-color: rgba(231,76,60,0.35); }}
.badge.unknown {{ color: var(--unknown); background: rgba(138,160,179,0.12); border-color: rgba(138,160,179,0.3); }}

.ring.good {{ color: var(--good); }}
.ring.warn {{ color: var(--warn); }}
.ring.bad  {{ color: var(--bad); }}

.card-note {{
    margin: 10px 0 0;
    font-size: 12px;
    color: var(--text-faint);
    max-width: 220px;
}}

/* ---------- Info grid (network / security) ---------- */

.info-panel {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: var(--radius);
    padding: 6px 22px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.2);
}}

.info-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 13px 0;
    border-bottom: 1px solid var(--panel-border);
}}

.info-row:last-child {{
    border-bottom: none;
}}

.info-key {{
    color: var(--text-dim);
    font-size: 13.5px;
}}

.info-value {{
    font-weight: 600;
    font-size: 13.5px;
    text-align: right;
}}

.info-value.wps-tag {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 12.5px;
    border: 1px solid transparent;
}}

.info-value.wps-tag.good {{ color: var(--good); background: rgba(46,204,113,0.12); border-color: rgba(46,204,113,0.35); }}
.info-value.wps-tag.warn {{ color: var(--warn); background: rgba(241,196,15,0.12); border-color: rgba(241,196,15,0.35); }}
.info-value.wps-tag.bad  {{ color: var(--bad);  background: rgba(231,76,60,0.12);  border-color: rgba(231,76,60,0.35); }}
.info-value.wps-tag.unknown {{ color: var(--unknown); background: rgba(138,160,179,0.12); border-color: rgba(138,160,179,0.3); }}

.two-col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
}}

@media (max-width: 700px) {{
    .two-col {{
        grid-template-columns: 1fr;
    }}
}}

/* ---------- Score breakdown ---------- */

.breakdown-panel {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: var(--radius);
    padding: 8px 22px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.2);
}}

.breakdown-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--panel-border);
}}

.breakdown-row:last-child {{
    border-bottom: none;
}}

.breakdown-label {{
    font-size: 13.5px;
    color: var(--text);
}}

.breakdown-points {{
    font-weight: 700;
    font-size: 13.5px;
    min-width: 46px;
    text-align: right;
}}

.pts-pos {{ color: var(--good); }}
.pts-neg {{ color: var(--bad); }}

/* ---------- Recommendations ---------- */

.rec-list {{
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 10px;
}}

.rec-card {{
    display: flex;
    align-items: flex-start;
    gap: 12px;
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 13px 16px;
    box-shadow: 0 3px 10px rgba(0,0,0,0.18);
}}

.rec-index {{
    flex: 0 0 auto;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: rgba(56,189,248,0.14);
    color: var(--accent);
    font-size: 12px;
    font-weight: 800;
    display: flex;
    align-items: center;
    justify-content: center;
}}

.rec-text {{
    font-size: 13.8px;
    color: var(--text);
}}

/* ---------- Footer ---------- */

.footer {{
    margin-top: 40px;
    text-align: center;
    font-size: 12px;
    color: var(--text-faint);
}}

@media (max-width: 560px) {{
    .header {{
        flex-direction: column;
        text-align: center;
    }}

    .info-row {{
        flex-direction: column;
        align-items: flex-start;
        gap: 4px;
    }}

    .info-value {{
        text-align: left;
    }}
}}

</style>
</head>
<body>
<div class="wrap">

    <div class="header">
        <div class="header-icon">
            <svg viewBox="0 0 24 24" fill="none">
                <path d="M12 21c4-2.5 7-6 7-11V6l-7-3-7 3v4c0 5 3 8.5 7 11Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
                <path d="M9.2 12.2l1.9 1.9 3.7-3.9" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </div>
        <div class="header-text">
            <h1>Wi-Fi Security Analyzer</h1>
            <p class="subtitle">Security Assessment Report</p>
            <p class="meta">Generated: {report_data['generated_at']}</p>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Security Scores</div>
        <div class="score-grid">

            <div class="score-card primary">
                <div class="score-card-label">
                    <svg class="icon" viewBox="0 0 24 24" fill="none">
                        <path d="M12 21c4-2.5 7-6 7-11V6l-7-3-7 3v4c0 5 3 8.5 7 11Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
                    </svg>
                    Overall Wi-Fi Security Score
                </div>
                <div class="ring {overall_class}" style="{overall_ring_style}">
                    <div class="ring-inner">
                        <span class="ring-score">{overall_score}</span>
                        <span class="ring-max">/100</span>
                    </div>
                </div>
                <div class="badge {overall_class}">{overall_rating}</div>
                <p class="card-note">
                    Evaluates the complete configuration: protocol,
                    encryption, WPS status, and password strength.
                </p>
            </div>

            {password_html}

        </div>
    </div>

    <div class="section two-col">

        <div>
            <div class="section-title">Network Information</div>
            <div class="info-panel">
                <div class="info-row">
                    <span class="info-key">SSID</span>
                    <span class="info-value">{n['ssid']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Interface</span>
                    <span class="info-value">{n['interface']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Connection Status</span>
                    <span class="info-value">{n['status']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Signal Strength</span>
                    <span class="info-value">{n['signal_strength']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Channel</span>
                    <span class="info-value">{n['channel']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Frequency</span>
                    <span class="info-value">{n['frequency']}</span>
                </div>
            </div>
        </div>

        <div>
            <div class="section-title">Security Configuration</div>
            <div class="info-panel">
                <div class="info-row">
                    <span class="info-key">Security Type</span>
                    <span class="info-value">{s['type']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Cipher</span>
                    <span class="info-value">{s['cipher']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">WPS Status</span>
                    <span class="info-value wps-tag {wps_class}">{s['wps_status']}</span>
                </div>
            </div>
        </div>

    </div>

    <div class="section">
        <div class="section-title">Score Breakdown</div>
        <div class="breakdown-panel">
{breakdown_rows}
        </div>
    </div>

    <div class="section">
        <div class="section-title">Recommendations</div>
        <ul class="rec-list">
{rec_items}
        </ul>
    </div>

    <div class="footer">
        Wi-Fi Security Analyzer &middot; Generated locally &middot; No data leaves this device
    </div>

</div>
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