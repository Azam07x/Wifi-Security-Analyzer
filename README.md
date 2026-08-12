# Wi-Fi Security Analyzer

A defensive, local-only tool that inspects the Wi-Fi connection your
computer is currently using, classifies its security configuration,
scores it, and gives concrete hardening recommendations.

## Project Objective

Help everyday users and students understand *how secure their own
Wi-Fi connection is* and *why* — without performing any kind of
attack, scan of networks they don't control, or password recovery.
It is built for authorized self-assessment and education only.

## Scope & Ethical Boundaries

This tool **only reads information your operating system already
exposes** about the network your machine is currently connected to
(via `netsh` on Windows or `nmcli`/`iw` on Linux). It does **not**:

- crack, guess, or brute-force any password
- perform Wi-Fi deauthentication or packet injection
- scan or attack networks you don't own or aren't authorized to test
- read stored Wi-Fi credentials from the OS
- transmit any data off your machine
- store or log the passphrase you type into the password analyzer

Only use this tool on networks and interfaces you own or have
explicit permission to assess.

## Features

1. **Network Information** — SSID, interface, status, security type,
   cipher, signal strength, channel/frequency, WPS status (each
   field individually degrades to "Unknown / Not available on this
   platform" if the OS doesn't expose it).
2. **Security Detection** — classifies Open / WEP / WPA / WPA2 /
   WPA3 / WPA2-WPA3 mixed mode, and TKIP vs AES/CCMP where available.
3. **Password Strength Analyzer** — local-only scoring of length,
   character variety, common-password and pattern checks. The
   passphrase is never stored, logged, or included in reports.
4. **Security Score (0–100)** — transparent, itemized breakdown of
   every point added or deducted.
5. **Recommendations** — specific, actionable hardening advice based
   on what was actually detected.
6. **Report Export** — TXT, JSON, or HTML, saved under `reports/`.
7. **Clean CLI** — simple numbered menu, `[+]/[!]/[-]` status
   indicators.

## Installation

Requires Python 3.8+. No third-party packages needed.

```bash
git clone <this-repo-or-copy-the-folder>
cd wifi_security_analyzer
```

(Optional, for isolation)
```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt   # installs nothing extra, documents deps
```

## How to Run

```bash
python3 main.py
```

You'll see a menu:

```
========================================
       WI-FI SECURITY ANALYZER
========================================
[1] Scan Current Wi-Fi Configuration
[2] Analyze Password Strength
[3] Generate Security Report
[4] View Security Recommendations
[5] Exit
```

## Windows Limitations

- Uses `netsh wlan show interfaces`, which requires an active Wi-Fi
  connection and a compatible wireless adapter/driver.
- WPS status is generally **not** exposed by `netsh` and will show as
  Unknown — this is expected, not a bug.
- Some fields (exact cipher detail) depend on driver/OS version.

## Linux Limitations

- Primary path uses `nmcli` (NetworkManager). If NetworkManager isn't
  managing your Wi-Fi (e.g. a headless setup using `wpa_supplicant`
  directly, or systemd-networkd), the tool falls back to `iw`, which
  exposes less security detail (cipher/WPS often Unknown).
- WPS status is not reliably available from either `nmcli` or `iw`
  and will usually show as Unknown.
- Some commands may require the user to be in an appropriate group
  (e.g. `netdev`) or may need elevated privileges depending on distro
  policy.

## How the Security Score Works

Starting from the detected protocol, points are added or subtracted
and every line is shown to the user:

| Factor | Points |
|---|---|
| WPA3 | +45 |
| WPA2/WPA3 mixed | +38 |
| WPA2-AES/CCMP | +35 |
| WPA2-TKIP | +20 |
| Legacy WPA | +10 |
| Security type unknown | +15 (neutral — can't fully assess) |
| WEP | -30 |
| Open/unencrypted | -40 |
| TKIP cipher present | -10 |
| WPS enabled | -10 |
| WPS disabled | +5 |
| Password strength | up to +25 (25% of the 0-100 password score) |

The final score is clamped to the 0–100 range. Every contributing
factor is printed in the "Breakdown" section so nothing is a black
box.

## Example Output

```
------------------------------------------
SSID              : HomeNetwork
Interface         : wlan0
Status            : Connected
Security          : WPA2
Cipher            : AES/CCMP
Signal Strength   : -48 dBm
Channel           : 6
Frequency         : 2437 MHz
WPS               : Unknown / Not available on this platform
------------------------------------------
[+] Risk level: LOW

Security Score: 72/100

Breakdown:
  +35  WPA2-AES/CCMP detected (good)
  +0   WPS status unknown
  +37  Password strength: Strong

Recommendations:
  1. Consider upgrading to WPA3 if your router and devices support it
  2. Check your router's admin panel to confirm WPS status
  3. Keep router firmware updated to patch known vulnerabilities
  4. Use a long, unique Wi-Fi passphrase not reused from other accounts
  5. Avoid connecting to or broadcasting open Wi-Fi networks
  6. Periodically review devices connected to your network
```

## Testing

```bash
python3 -m unittest test_analyzer.py -v
```

Covers: password strength scoring, security classification (Open /
WEP / WPA / WPA2 / WPA3 / mixed), score calculation and bounds,
recommendation generation and de-duplication, and report export
(TXT/JSON/HTML) — all using synthetic input, no live scan required.

## Security & Privacy

- 100% local execution — no network calls to external servers.
- Passphrases are never written to disk, logged, or embedded in
  generated reports.
- Only standard, read-only OS commands are used (`netsh`, `nmcli`,
  `iw`) via `subprocess` with `shell=False`.
- No fields are fabricated: anything the OS doesn't expose is clearly
  labeled "Unknown / Not available on this platform."

## Future Improvements

- Optional GUI/web dashboard (e.g. a local Flask/Tkinter front end)
- macOS support via `airport`/`networksetup`
- Historical trend tracking across repeated scans (score over time)
- Router firmware-version lookup against a local CVE reference list
  (still local-only, no external calls without explicit user opt-in)
- Multi-language recommendation output
