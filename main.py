#!/usr/bin/env python3
"""
main.py
-------
Wi-Fi Security Analyzer — CLI entry point.

Defensive, local-only tool. See README.md for full details and
scope/limitations.
"""

import getpass
import sys

import scanner
import security_analyzer
import password_analyzer
import scoring
import recommendations as rec_module
import report_generator
from utils import print_header, print_kv_block, UNKNOWN

LAST_ASSESSMENT = {}  # in-memory only, cleared on exit; never written to disk directly


def scan_and_assess(show_output=True):
    """Run a full scan + classification + scoring pass. Returns the assessment dict."""
    network_info = scanner.scan_current_network()
    security_info = security_analyzer.classify_security(
        network_info.get("security"), network_info.get("encryption")
    )
    wps_status = security_analyzer.classify_wps(network_info.get("wps"))

    if show_output:
        print()
        print_header("WI-FI SECURITY ANALYZER")
        print_kv_block([
            ("SSID", network_info.get("ssid", UNKNOWN)),
            ("Interface", network_info.get("interface", UNKNOWN)),
            ("Status", network_info.get("status", UNKNOWN)),
            ("Security", security_info.get("type", UNKNOWN)),
            ("Cipher", security_info.get("cipher", UNKNOWN)),
            ("Signal Strength", network_info.get("signal_strength", UNKNOWN)),
            ("Channel", network_info.get("channel", UNKNOWN)),
            ("Radio Type", network_info.get("radio_type", UNKNOWN)),
            ("Frequency", network_info.get("frequency", UNKNOWN)),
            ("WPS", wps_status),
        ])

        risk = security_info.get("risk_level", UNKNOWN)
        if risk in ("critical", "high"):
            print(f"[-] Risk level: {risk.upper()}")
        elif risk in ("medium",):
            print(f"[!] Risk level: {risk.upper()}")
        elif risk in ("low", "none"):
            print(f"[+] Risk level: {risk.upper()}")
        else:
            print(f"[!] Risk level: {UNKNOWN}")

    LAST_ASSESSMENT.update({
        "network_info": network_info,
        "security_info": security_info,
        "wps_status": wps_status,
    })
    return LAST_ASSESSMENT


def run_password_analysis(show_output=True):
    print()
    print("Password is analyzed locally only — never stored, logged, or transmitted.")
    try:
        pwd = getpass.getpass("Enter Wi-Fi passphrase to analyze (input hidden): ")
    except Exception:
        pwd = input("Enter Wi-Fi passphrase to analyze: ")

    result = password_analyzer.analyze_password_strength(pwd)
    pwd = None  # drop reference immediately after analysis
    del pwd

    if show_output:
        print()
        print(f"Password Strength: {result['label']}")
        print(f"Score: {result['score']}/100")
        print()
        print("Recommendations:")
        for r in result["recommendations"]:
            print(f"  - {r}")

    LAST_ASSESSMENT["password_result"] = result
    return result


def generate_report():
    if "network_info" not in LAST_ASSESSMENT:
        print("\n[!] Run a scan first (option 1) before generating a report.")
        return

    score_result = scoring.calculate_security_score(
        LAST_ASSESSMENT["security_info"],
        LAST_ASSESSMENT["wps_status"],
        LAST_ASSESSMENT.get("password_result"),
    )
    recs = rec_module.generate_recommendations(
        LAST_ASSESSMENT["security_info"],
        LAST_ASSESSMENT["wps_status"],
        LAST_ASSESSMENT.get("password_result"),
    )
    report_data = report_generator.build_report_data(
        LAST_ASSESSMENT["network_info"],
        LAST_ASSESSMENT["security_info"],
        LAST_ASSESSMENT["wps_status"],
        score_result,
        recs,
        LAST_ASSESSMENT.get("password_result"),
    )

    print()
    print("Export format:")
    print("  [1] TXT")
    print("  [2] JSON")
    print("  [3] HTML")
    choice = input("Choose format: ").strip()
    fmt_map = {"1": "txt", "2": "json", "3": "html"}
    fmt = fmt_map.get(choice)
    if not fmt:
        print("[!] Invalid choice.")
        return

    path = report_generator.EXPORTERS[fmt](report_data)
    print(f"[+] Report saved to: {path}")


def view_recommendations():
    if "network_info" not in LAST_ASSESSMENT:
        print("\n[!] Run a scan first (option 1) to get tailored recommendations.")
        return

    recs = rec_module.generate_recommendations(
        LAST_ASSESSMENT["security_info"],
        LAST_ASSESSMENT["wps_status"],
        LAST_ASSESSMENT.get("password_result"),
    )
    score_result = scoring.calculate_security_score(
        LAST_ASSESSMENT["security_info"],
        LAST_ASSESSMENT["wps_status"],
        LAST_ASSESSMENT.get("password_result"),
    )

    print()
    print(f"Security Score: {score_result['score']}/100")
    print()
    print("Breakdown:")
    for label, points in score_result["breakdown"]:
        sign = "+" if points >= 0 else ""
        print(f"  {sign}{points}  {label}")
    print()
    print("Recommendations:")
    for i, r in enumerate(recs, 1):
        print(f"  {i}. {r}")


def print_menu():
    print()
    print("=" * 40)
    print("WI-FI SECURITY ANALYZER".center(40))
    print("=" * 40)
    print("[1] Scan Current Wi-Fi Configuration")
    print("[2] Analyze Password Strength")
    print("[3] Generate Security Report")
    print("[4] View Security Recommendations")
    print("[5] Exit")
    print("=" * 40)


def main():
    print("Wi-Fi Security Analyzer — defensive, local-only assessment tool.")
    print("This tool only analyzes networks/interfaces you own or are authorized to test.")

    while True:
        print_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            scan_and_assess()
        elif choice == "2":
            run_password_analysis()
        elif choice == "3":
            generate_report()
        elif choice == "4":
            view_recommendations()
        elif choice == "5":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("[!] Invalid option, please choose 1-5.")


if __name__ == "__main__":
    main()
