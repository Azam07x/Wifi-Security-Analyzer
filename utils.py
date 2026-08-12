"""
utils.py
--------
Shared helper functions: platform detection, safe subprocess execution,
and consistent "Unknown / Not available" handling.

No network calls are ever made from this module. Everything here is
local, read-only, and defensive in nature.
"""

import platform
import subprocess

UNKNOWN = "Unknown / Not available on this platform"


def get_os():
    """Return a normalized OS name: 'windows', 'linux', or 'other'."""
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system.startswith("linux"):
        return "linux"
    return "other"


def run_command(command, timeout=8):
    """
    Run a read-only system command safely and return its stdout as text.

    Returns None on any failure (missing binary, permission error,
    timeout, non-zero exit) so callers can fall back to UNKNOWN instead
    of crashing. This function never raises to the caller.

    `command` must be a list (e.g. ["nmcli", "-t", "dev", "wifi"]) —
    shell=False is used deliberately to avoid shell injection risk.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    except PermissionError:
        return None
    except Exception:
        # Defensive catch-all: never let an environment quirk crash the app.
        return None


def safe_get(d, key, default=UNKNOWN):
    """Dict lookup that treats None/empty string as missing too."""
    value = d.get(key, default)
    if value in (None, ""):
        return default
    return value


def print_header(title, width=42):
    print("=" * width)
    print(title.center(width))
    print("=" * width)


def print_kv_block(pairs, width=42):
    """Print a list of (label, value) tuples in an aligned block."""
    print("-" * width)
    for label, value in pairs:
        print(f"{label:<18}: {value}")
    print("-" * width)
