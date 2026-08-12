# Wi-Fi Security Analyzer

> A lightweight, privacy-focused Python utility designed to assess the security posture of a locally connected Wi-Fi network.

## Overview

**Wi-Fi Security Analyzer** is a defensive, local-first security assessment tool built with Python.

The project examines the configuration of the currently connected wireless network, evaluates its security characteristics, analyzes Wi-Fi password strength, and produces an interpretable overall security assessment.

Rather than performing intrusive attacks or attempting to compromise a network, the analyzer focuses on **visibility, risk awareness, and practical security recommendations**.

---

## Key Capabilities

- 🔍 **Wireless Configuration Analysis**  
  Identifies essential information about the currently connected Wi-Fi network.

- 🔐 **Security Protocol Detection**  
  Determines the wireless security protocol and encryption configuration.

- 🛡️ **WPS Assessment**  
  Evaluates WPS availability whenever the underlying platform exposes the required information.

- 🔑 **Password Strength Analysis**  
  Locally evaluates Wi-Fi passphrase strength without storing or transmitting the original password.

- 📊 **Security Scoring Engine**  
  Combines multiple security factors into a single interpretable Wi-Fi security score.

- 💡 **Security Recommendations**  
  Generates actionable recommendations based on the detected configuration.

- 📄 **Report Generation**  
  Exports assessment results in TXT, JSON, and HTML formats.

- 🧪 **Automated Testing**  
  Includes a dedicated test suite covering the core analysis and scoring logic.

---

## Security Assessment Model

The analyzer evaluates the Wi-Fi configuration across several independent dimensions:

```text
Security Protocol
        +
Encryption / Cipher
        +
WPS Configuration
        +
Password Strength
        ↓
Overall Wi-Fi Security Assessment
```

The resulting **Overall Wi-Fi Security Score** represents the security posture of the complete Wi-Fi configuration.

### Password Score ≠ Overall Security Score

The project deliberately keeps these two measurements separate.

For example:

```text
Password Strength
55/100 — Fair

Overall Wi-Fi Security
84/100 — Good
```

This is not a contradiction.

The **Password Strength Score** evaluates only the quality of the Wi-Fi passphrase.

The **Overall Wi-Fi Security Score** evaluates the broader security configuration, including the wireless protocol, encryption, WPS status, and password strength.

This distinction helps prevent users from confusing password quality with the security of the entire wireless configuration.

---

## Security Scoring

The scoring engine evaluates multiple security factors, including:

| Security Factor | Assessment |
|---|---|
| WPA3 | Strong |
| WPA2-AES/CCMP | Strong |
| WPA2-TKIP | Legacy / Weaker |
| Legacy WPA | Weak |
| WEP | Severely Insecure |
| Open / Unencrypted | Severely Insecure |
| TKIP | Legacy / Weaker |
| WPS Enabled | Additional Risk |
| WPS Disabled | Positive Factor |
| Password Strength | Contributes to Overall Score |

The final score is normalized to a **0–100 range**.

Every contributing factor is exposed through the score breakdown, making the assessment transparent rather than treating the result as a black box.

---

## Project Architecture

```text
wifi_security_analyzer/
│
├── main.py
├── scanner.py
├── security_analyzer.py
├── password_analyzer.py
├── scoring.py
├── recommendations.py
├── report_generator.py
├── utils.py
├── test_analyzer.py
├── requirements.txt
├── README.md
└── reports/
```

### Core Components

**`main.py`**  
Provides the interactive command-line interface and coordinates the complete assessment workflow.

**`scanner.py`**  
Collects locally available wireless network information.

**`security_analyzer.py`**  
Classifies security protocols, encryption methods, and WPS status.

**`password_analyzer.py`**  
Performs local Wi-Fi password-strength analysis.

**`scoring.py`**  
Calculates the overall Wi-Fi security score and provides a transparent scoring breakdown.

**`recommendations.py`**  
Generates security recommendations based on the detected configuration.

**`report_generator.py`**  
Produces TXT, JSON, and HTML assessment reports.

**`utils.py`**  
Contains shared utility functions used throughout the application.

**`test_analyzer.py`**  
Validates core functionality through automated tests.

---

## Installation

### Prerequisites

- Python 3.10 or later
- Windows operating system
- Functional Wi-Fi adapter
- Permission to inspect the local network configuration

### Setup

Clone the repository:

```bash
git clone https://github.com/Azam07x/Wifi-Security-Analyzer.git
```

Navigate into the project directory:

```bash
cd Wifi-Security-Analyzer
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Analyzer

Launch the application with:

```bash
python main.py
```

The interactive CLI provides the following options:

```text
[1] Scan Current Wi-Fi Configuration
[2] Analyze Password Strength
[3] Generate Security Report
[4] View Security Recommendations
[5] Exit
```

---

## Example Assessment

A typical assessment may display information such as:

```text
WI-FI SECURITY ANALYZER

SSID              : ExampleNetwork
Interface         : Wi-Fi
Status            : connected
Security          : WPA3
Cipher            : AES/CCMP
Signal Strength   : 80%
WPS               : Unknown / Not available on this platform

Risk Level        : NONE
```

### Password Assessment

```text
Password Strength : Fair
Score             : 55/100
```

### Overall Security Assessment

```text
Overall Security Score  : 84/100
Overall Security Rating : Good
```

The two scores intentionally measure different aspects of the Wi-Fi configuration.

---

## Report Generation

The analyzer supports three report formats:

```text
TXT
JSON
HTML
```

Generated reports can include:

- Network configuration
- Security protocol
- Encryption details
- WPS status
- Password-strength assessment
- Overall security score
- Score breakdown
- Security recommendations

Generated report files are stored locally in the `reports/` directory.

Report files are excluded from version control through `.gitignore`.

---

## Privacy by Design

Privacy is a core design principle of this project.

The Wi-Fi passphrase is analyzed **locally in memory** and is never:

- Stored permanently
- Written to generated reports
- Logged to the console
- Transmitted over the network

Only the derived password-strength rating and score are retained for the current assessment.

The tool is designed to provide useful security insights without exposing the original Wi-Fi password.

---

## Testing

The project includes an automated test suite using `pytest`.

Run the complete test suite with:

```bash
python -m pytest
```

Current test status:

```text
29 passed
```

The test suite helps verify the reliability of the security classification, password analysis, scoring, and recommendation logic.

---

## Limitations

The analyzer is intentionally designed as a **defensive security assessment utility**, rather than an offensive Wi-Fi auditing framework.

Some information, particularly WPS status, may be unavailable depending on:

- Operating system
- Wi-Fi adapter
- Device drivers
- Platform-specific capabilities

The security score is an **assessment model**, not a formal security certification or guarantee of network safety.

A high score should therefore be interpreted as an indication of a comparatively strong configuration, not as proof that the network is completely secure.

---

## Ethical Scope

This project is intended exclusively for:

- Personally owned networks
- Authorized security assessments
- Educational environments
- Cybersecurity laboratories

It does **not** attempt to:

- Crack Wi-Fi passwords
- Exploit wireless networks
- Bypass authentication
- Intercept network traffic
- Attack unauthorized systems

The objective is straightforward:

> **Understand the security posture. Identify weaknesses. Improve the configuration.**

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application |
| Pytest | Automated testing |
| Wi-Fi / Network APIs | Local configuration analysis |
| HTML | Human-readable reports |
| JSON | Structured report output |
| TXT | Lightweight report output |
| Git & GitHub | Version control and project hosting |

**Database:** Not required.

---

## Project Highlights

This project demonstrates practical experience with:

- Python modular architecture
- Wireless network configuration analysis
- Wi-Fi security concepts
- Security scoring methodologies
- Password-strength evaluation
- Defensive cybersecurity practices
- Automated testing
- Structured report generation
- Privacy-conscious software design
- Git and GitHub workflow

---

## Future Improvements

Potential future enhancements include:

- Cross-platform support for Linux
- Improved WPS detection
- More detailed wireless security metrics
- Additional report visualizations
- Historical assessment comparison
- Network device visibility
- More granular risk classification

These improvements are intentionally kept outside the current scope to maintain a lightweight and focused implementation.

---

## Author

**Mohd Azam Ansari**

*MCA Student | Networking & Cybersecurity Enthusiast*

Interested in:

**Networking · Cybersecurity · Python · Linux · Security Analysis**

---

## Disclaimer

This software is provided for educational and defensive security assessment purposes.

Only analyze networks and systems that you own or have explicit authorization to assess.

The results generated by this tool are intended to improve security awareness and configuration hygiene and should not be considered a formal security audit or certification.