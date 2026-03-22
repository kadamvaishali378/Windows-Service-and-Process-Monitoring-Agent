"""
Service Detection Module
------------------------
Analyzes Windows services for suspicious indicators.
Generates alerts similar to process detector.
"""

import os

# suspicious execution locations
SUSPICIOUS_PATHS = [
    "temp",
    "appdata",
    "users",
    "downloads",
    "desktop"
]

def detect_suspicious_services(services):
    alerts = []

    for s in services:
        name = (s.get("name") or "").lower()
        path = (s.get("path") or "").lower()
        start_type = (s.get("start_type") or "").lower()

        # --- Rule 1: Service running from suspicious location ---
        if any(p in path for p in SUSPICIOUS_PATHS):
            alerts.append({
                "type": "Service running from suspicious location",
                "service": s.get("name"),
                "path": s.get("path"),
                "severity": "HIGH"
            })

        # --- Rule 2: Service with missing executable path ---
        if not path or path.strip() == "":
            alerts.append({
                "type": "Service missing executable path",
                "service": s.get("name"),
                "severity": "MEDIUM"
            })

        # --- Rule 3: Unknown auto-start service ---
        if start_type == "auto" and not name.startswith(("win", "microsoft", "intel", "amd")):
            alerts.append({
                "type": "Unknown auto-start service",
                "service": s.get("name"),
                "severity": "MEDIUM"
            })

    return alerts
