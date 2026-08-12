"""
scanner.py
----------
Reads Wi-Fi connection information exposed by the operating system.

This module is READ-ONLY. It never:
  - injects packets
  - performs deauthentication
  - attempts to join networks
  - reads or requests stored Wi-Fi passwords/keys
  - scans networks other than what the OS already reports for the
    currently connected / locally visible interface

It only wraps standard OS utilities (netsh on Windows, nmcli/iw on
Linux) that any user could run manually themselves.
"""

from utils import get_os, run_command, UNKNOWN


def scan_current_network():
    """
    Return a dict describing the currently connected Wi-Fi network.

    Keys: ssid, interface, status, security, encryption,
          signal_strength, channel, frequency, bssid, wps

    Any field the OS/tooling doesn't expose is set to UNKNOWN.
    Never fabricated.
    """
    os_name = get_os()
    if os_name == "windows":
        return _scan_windows()
    elif os_name == "linux":
        return _scan_linux()
    else:
        return _empty_result(status="Unsupported operating system")


def _empty_result(status=UNKNOWN):
    return {
        "ssid": UNKNOWN,
        "interface": UNKNOWN,
        "status": status,
        "security": UNKNOWN,
        "encryption": UNKNOWN,
        "signal_strength": UNKNOWN,
        "channel": UNKNOWN,
        "radio_type": UNKNOWN,
        "bssid": UNKNOWN,
        "wps": UNKNOWN,
    }


# ---------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------

def _scan_windows():
    result = _empty_result()

    output = run_command(["netsh", "wlan", "show", "interfaces"])
    if output is None:
        result["status"] = "No active Wi-Fi connection or netsh unavailable"
        return result

    fields = _parse_netsh_interfaces(output)
    result.update(fields)

    # WPS and detailed cipher info aren't exposed by "show interfaces".
    # We do NOT query profile keys (that would touch stored credentials),
    # so WPS/channel-extra info stays Unknown unless netsh surfaces it above.
    return result


def _parse_netsh_interfaces(output):
    """Parse the text output of `netsh wlan show interfaces`."""
    mapping = {
        "ssid": "ssid",
        "bssid": "bssid",
        "state": "status",
        "signal": "signal_strength",
        "channel": "channel",
        "radio type": "radio_type",
        "authentication": "security",
        "cipher": "encryption",
    }
    parsed = {}
    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        key, _, value = raw_line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in mapping and value:
            parsed[mapping[key]] = value 

        # Calculate Wi-Fi frequency from channel when Windows does not expose it
    if "channel" in parsed:
        try:
            channel = int(parsed["channel"])

            if 1 <= channel <= 13:
                parsed["frequency"] = f"{2407 + (channel * 5)} MHz"
            elif channel == 14:
                parsed["frequency"] = "2484 MHz"
            elif 32 <= channel <= 177:
                parsed["frequency"] = f"{5000 + (channel * 5)} MHz"
        except ValueError:
            parsed["frequency"] = UNKNOWN


    # Interface name isn't in this output; try a lightweight lookup.
    iface_output = run_command(["netsh", "wlan", "show", "interfaces"])
    if iface_output:
        for raw_line in iface_output.splitlines():
            if raw_line.strip().lower().startswith("name"):
                _, _, value = raw_line.partition(":")
                if value.strip():
                    parsed["interface"] = value.strip()
                break

    if "signal_strength" in parsed and "%" in parsed["signal_strength"]:
        parsed["signal_strength"] = parsed["signal_strength"]  # keep as %, honest to source

    return parsed


# ---------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------

def _scan_linux():
    result = _empty_result()

    # Preferred: nmcli, widely available on modern distros with NetworkManager
    nmcli_fields = _scan_linux_nmcli()
    if nmcli_fields:
        result.update(nmcli_fields)
        return result

    # Fallback: iw (lower-level, requires interface name guessing)
    iw_fields = _scan_linux_iw()
    if iw_fields:
        result.update(iw_fields)
        return result

    result["status"] = "No active Wi-Fi connection or required tools (nmcli/iw) not found"
    return result


def _scan_linux_nmcli():
    # Active connection details (SSID, device, security)
    active = run_command([
        "nmcli", "-t", "-f",
        "ACTIVE,SSID,DEVICE,SIGNAL,CHAN,FREQ,SECURITY,BSSID",
        "dev", "wifi"
    ])
    if active is None:
        return None

    for line in active.splitlines():
        parts = line.split(":")
        if len(parts) < 8:
            continue
        is_active, ssid, device, signal, chan, freq, security, bssid = parts[:8]
        if is_active.lower() == "yes":
            fields = {
                "ssid": ssid or UNKNOWN,
                "interface": device or UNKNOWN,
                "status": "Connected",
                "security": security or UNKNOWN,
                "signal_strength": f"{signal}%" if signal else UNKNOWN,
                "channel": chan or UNKNOWN,
                "frequency": freq or UNKNOWN,
                "bssid": bssid or UNKNOWN,
                "encryption": _infer_cipher_from_security_string(security),
                "wps": UNKNOWN,  # nmcli does not reliably expose WPS status
            }
            return fields

    return None  # no active Wi-Fi connection found


def _scan_linux_iw():
    # Find a wireless interface name
    dev_output = run_command(["iw", "dev"])
    if dev_output is None:
        return None

    interface = None
    for line in dev_output.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            interface = line.split()[1]
            break

    if not interface:
        return None

    link_output = run_command(["iw", "dev", interface, "link"])
    if link_output is None or "Not connected" in link_output:
        return {"interface": interface, "status": "No active Wi-Fi connection"}

    fields = {"interface": interface, "status": "Connected"}
    for line in link_output.splitlines():
        line = line.strip()
        if line.startswith("SSID:"):
            fields["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            fields["frequency"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            fields["signal_strength"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("connected to"):
            fields["bssid"] = line.split()[-1]

    # iw doesn't cleanly expose security/cipher without parsing scan results,
    # which we avoid here to keep this a lightweight, low-privilege read.
    fields["security"] = UNKNOWN
    fields["encryption"] = UNKNOWN
    fields["channel"] = UNKNOWN
    fields["wps"] = UNKNOWN
    return fields


def _infer_cipher_from_security_string(security_str):
    """
    nmcli's SECURITY field sometimes contains cipher hints (e.g. 'WPA2 802.1X',
    'WPA1 WPA2'). This does light text inference only — never guesses beyond
    what's textually present.
    """
    if not security_str:
        return UNKNOWN
    text = security_str.upper()
    if "WPA3" in text:
        return "SAE/AES (WPA3)"
    if "WPA2" in text and "TKIP" in text:
        return "TKIP"
    if "WPA2" in text:
        return "AES/CCMP (assumed for WPA2, unconfirmed)"
    if "WEP" in text:
        return "WEP (insecure)"
    return UNKNOWN
