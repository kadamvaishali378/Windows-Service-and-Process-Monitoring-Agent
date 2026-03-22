"""
Detector Module
---------------
Contains logic to detect suspicious behaviour in processes.

Includes:
1. Suspicious parent-child process relationships
2. Suspicious execution locations (with whitelist to reduce false positives)
3. Unauthorized processes not in baseline whitelist (with Windows/system exclusions)
"""

import os
from datetime import datetime


def now():
    """Return formatted timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =========================
# 1. Parent-Child Detection
# =========================
def detect_suspicious_relationships(processes):
    """
    Detect suspicious parent-child process chains.
    Example: browser spawning cmd or powershell.
    """

    suspicious_pairs = {
        ("winword.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("chrome.exe", "cmd.exe"),
        ("chrome.exe", "powershell.exe"),
        ("msedge.exe", "cmd.exe"),
        ("msedge.exe", "powershell.exe"),
        ("outlook.exe", "powershell.exe"),
    }

    alerts = []
    process_dict = {p["pid"]: p for p in processes}

    for p in processes:
        parent = process_dict.get(p.get("ppid"))
        if not parent:
            continue

        parent_name = (parent.get("name") or "").lower()
        child_name = (p.get("name") or "").lower()

        if (parent_name, child_name) in suspicious_pairs:
            alerts.append({
                "timestamp": now(),
                "severity": "HIGH",
                "type": "Suspicious Parent-Child",
                "parent": parent_name,
                "child": child_name,
                "pid": p.get("pid")
            })

    return alerts


# =========================
# 2. Suspicious Locations
# =========================
def detect_suspicious_locations(processes):
    """
    Detect processes running from commonly abused folders.
    Uses whitelist to avoid flagging normal developer apps.
    """

    alerts = []

    suspicious_paths = [
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\"
    ]

    whitelist = {
        "code.exe",
        "python.exe",
        "browser_assistant.exe",
        "discord.exe",
        "slack.exe",
        "teams.exe",
        "zoom.exe"
    }

    for p in processes:
        name = (p.get("name") or "").lower()
        path = (p.get("path") or "").lower()

        if name in whitelist:
            continue

        if any(sp in path for sp in suspicious_paths):
            alerts.append({
                "timestamp": now(),
                "severity": "MEDIUM",
                "type": "Suspicious Execution Path",
                "process": p.get("name"),
                "path": p.get("path"),
                "pid": p.get("pid")
            })

    return alerts


# =========================
# 3. Unauthorized Processes
# =========================
def detect_unauthorized_processes(processes, whitelist_file="baseline_processes.txt"):
    """
    Detect processes not present in the baseline whitelist.
    Ignores core Windows/system processes automatically.
    """

    system_safe = {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsaiso.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe"
    }

    common_safe = {
        "msedge.exe",
        "msedgewebview2.exe",
        "chrome.exe",
        "code.exe",
        "python.exe",
        "notepad.exe",
        "cmd.exe"
    }

    whitelist = set()
    if os.path.exists(whitelist_file):
        with open(whitelist_file, "r") as f:
            whitelist = {line.strip().lower() for line in f if line.strip()}
    else:
        print("⚠ baseline_processes.txt not found. Run baseline first.")

    alerts = []

    for p in processes:
        name = (p.get("name") or "").lower()

        if name in system_safe:
            continue
        if name in common_safe:
            continue
        if name in whitelist:
            continue

        if name:
            alerts.append({
                "timestamp": now(),
                "severity": "HIGH",
                "type": "Unauthorized Process",
                "process": p.get("name"),
                "pid": p.get("pid"),
                "path": p.get("path")
            })

    return alerts
