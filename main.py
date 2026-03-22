"""
Main Monitoring Agent
---------------------
Windows Service & Process Monitoring Agent

Performs:
1. Directory setup
2. Process collection
3. Behaviour detection
4. Baseline comparison
5. Service audit with detection
6. Alert logging
7. Report generation
8. Continuous monitoring loop
"""

import os
import time
import json
from datetime import datetime

from service_audit import get_services
from process_monitor import get_running_processes
from detector import (
    detect_suspicious_locations,
    detect_suspicious_relationships,
    detect_unauthorized_processes
)

# ✅ NEW: service detection
from service_detector import detect_suspicious_services

# ✅ NEW: report generator
from report_generator import generate_report

BASELINE_FILE = "baseline.json"
LOG_FILE = "logs/alerts.log"


# ---------------- DIRECTORY SETUP ----------------

def ensure_directories():
    folders = ["logs", "reports", "docs"]
    for folder in folders:
        os.makedirs(folder, exist_ok=True)


# ---------------- BASELINE HANDLING ----------------

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return set()
    try:
        with open(BASELINE_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()


def compare_with_baseline(processes, baseline):
    """Detect new processes not present in baseline."""
    alerts = []
    for p in processes:
        name = (p.get("name") or "").lower()
        if name and name not in baseline:
            alerts.append({
                "type": "New Process Detected",
                "process": p.get("name"),
                "pid": p.get("pid"),
                "severity": "MEDIUM"
            })
    return alerts


# ---------------- LOGGING ----------------

def log_alerts(alerts):
    if not alerts:
        return

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        for alert in alerts:
            severity = alert.get("severity", "INFO")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} [{severity}] {alert}\n")


# ---------------- PROCESS MONITORING ----------------

def monitor_processes():
    print("\n🔍 Collecting running processes...\n")

    processes = get_running_processes()
    print(f"Total Processes Found: {len(processes)}")

    baseline = load_baseline()
    all_alerts = []

    # Parent-child behaviour
    print("\nAnalyzing parent-child behaviour...")
    rel_alerts = detect_suspicious_relationships(processes)
    for a in rel_alerts:
        a["severity"] = "HIGH"
    all_alerts.extend(rel_alerts)

    # Suspicious locations
    print("Checking execution locations...")
    loc_alerts = detect_suspicious_locations(processes)
    for a in loc_alerts:
        a["severity"] = "MEDIUM"
    all_alerts.extend(loc_alerts)

    # Unauthorized processes
    print("Checking whitelist violations...")
    unauth_alerts = detect_unauthorized_processes(processes)
    for a in unauth_alerts:
        a["severity"] = "LOW"
    all_alerts.extend(unauth_alerts)

    # Baseline comparison
    print("Comparing with baseline...")
    baseline_alerts = compare_with_baseline(processes, baseline)
    all_alerts.extend(baseline_alerts)

    # Display alerts
    if all_alerts:
        print("\n🚨 PROCESS ALERTS:\n")
        for alert in all_alerts[:10]:
            print(alert)
    else:
        print("\n✅ No suspicious processes detected.")

    log_alerts(all_alerts)
    return processes, all_alerts


# ---------------- SERVICE AUDIT ----------------

def audit_services():
    print("\n🔧 Auditing Windows services...\n")

    services = get_services()
    print(f"Total Services Found: {len(services)}")

    service_alerts = detect_suspicious_services(services)

    if service_alerts:
        print("\n🚨 SERVICE ALERTS:\n")
        for a in service_alerts[:10]:
            print(a)
    else:
        print("✅ No suspicious services detected.")

    log_alerts(service_alerts)
    return services, service_alerts


# ---------------- MONITOR CYCLE ----------------

def run_monitoring_cycle():
    processes, process_alerts = monitor_processes()
    services, service_alerts = audit_services()

    all_alerts = process_alerts + service_alerts

    # ✅ Generate full SOC-style report
    generate_report(processes, all_alerts)

    print("\n✔ Monitoring cycle completed.\n")
    print("-------------------------------------------------------------------------------------------")


# ---------------- MAIN LOOP ----------------

def main():
    print("\n🛡  Windows Monitoring Agent Started\n")
    ensure_directories()

    try:
        while True:
            run_monitoring_cycle()
            print("Next scan in 60 seconds...\n")
            time.sleep(60)

    except KeyboardInterrupt:
        print("\nAgent stopped by user.")


if __name__ == "__main__":
    main()
