"""
Report Generator Module
-----------------------
Creates a summarized security report after each monitoring cycle.
"""

from datetime import datetime


def generate_report(processes, alerts, filename="reports/final_report.txt"):
    """
    Generate a structured security report.
    """

    total_processes = len(processes)

    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low = sum(1 for a in alerts if a.get("severity") == "LOW")

    total_alerts = len(alerts)

    # Determine risk level
    if high > 0:
        risk = "HIGH"
    elif medium > 3:
        risk = "MEDIUM"
    elif total_alerts > 0:
        risk = "LOW"
    else:
        risk = "SAFE"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("WINDOWS SECURITY MONITORING REPORT\n")
        f.write("=" * 40 + "\n")
        f.write(f"Generated: {datetime.now()}\n\n")

        f.write(f"Total Running Processes: {total_processes}\n")
        f.write(f"Total Alerts: {total_alerts}\n\n")

        f.write("Severity Breakdown:\n")
        f.write(f"  HIGH   : {high}\n")
        f.write(f"  MEDIUM : {medium}\n")
        f.write(f"  LOW    : {low}\n\n")

        f.write(f"Overall System Risk Level: {risk}\n\n")

        f.write("Detailed Alerts:\n")
        f.write("-" * 40 + "\n")

        if alerts:
            for a in alerts:
                f.write(str(a) + "\n")
        else:
            f.write("No suspicious activity detected.\n")

    print(f"📄 Security report generated: {filename}")
