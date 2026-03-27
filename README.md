# 🛡️ Windows Service & Process Monitoring Agent

### Cybersecurity Monitoring Tool for Detecting Suspicious Processes & Services

🔗 **Project Repository:** [https://github.com/kadamvaishali378/Windows-Service-and-Process-Monitoring-Agent](https://github.com/kadamvaishali378/Windows-Service-and-Process-Monitoring-Agent)

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen)

---

## 📌 Overview

The **Windows Service & Process Monitoring Agent** is a cybersecurity tool developed as part of an internship project to monitor system processes and Windows services for suspicious activity.

It focuses on detecting behavior-based threats such as:

* Suspicious parent–child process relationships
* Unauthorized or unknown processes
* Execution from unsafe directories (Temp, AppData, Downloads)
* Malicious or abnormal Windows services used for persistence

The system uses **behavioral analysis and baseline comparison** instead of traditional signature-based detection.

---

## 🚀 Key Features

✔ Real-time process monitoring
✔ Parent–child relationship analysis
✔ Unauthorized process detection
✔ Suspicious execution path detection
✔ Windows service auditing
✔ Rule-based threat detection
✔ Alert generation with severity levels
✔ Structured report generation

---

## 🛠️ Tech Stack

| Technology   | Purpose                     |
| ------------ | --------------------------- |
| Python       | Core logic                  |
| psutil       | Process monitoring          |
| WMI          | Windows service enumeration |
| win32service | Service management          |
| datetime     | Timestamp generation        |
| os           | File path handling          |

---

## 🐍 Python Version

Python 3.x (Recommended: Python 3.8 or above)

---

## ⚙️ Installation

```bash
# Clone repository
git clone https://github.com/your-username/windows-process-monitor.git

# Navigate to project
cd windows-process-monitor

# Run application
python main.py
```

---

## 🧪 Usage

1. Run the monitoring script
2. System scans processes and services
3. Detection rules are applied
4. Alerts are generated for suspicious activity
5. Final report is displayed

---

## 🔍 Test Scenarios

### 1. Suspicious Parent–Child Process

Run:

```
winword.exe → powershell.exe
```

### 2. Execution from Temp Directory

Run any `.exe` from:

```
C:\Users\<User>\AppData\Local\Temp
```

### 3. Unauthorized Process

Run a process not in baseline list

### 4. Suspicious Service

Create or run a service from unusual path

---

## 🧠 Detection Techniques

### 🔹 Parent–Child Monitoring

Detects abnormal execution chains such as:

* Word launching PowerShell

### 🔹 Execution Path Analysis

Flags processes running from:

* Temp
* Downloads
* AppData

### 🔹 Baseline Comparison

* Compares running processes with trusted list
* Flags unknown processes

### 🔹 Service Audit

* Detects suspicious services
* Identifies abnormal startup paths

### 🔹 Rule-Based Detection

* Uses predefined rules
* Generates alerts based on behavior

---

## 🏗️ System Architecture

```
Processes & Services → Data Collection Modules
                      → Behavior Analysis Engine
                      → Baseline Comparison
                      → Detection Engine
                      → Alert System
                      → Report Generator
```

---

## 🔄 Workflow

1. Enumerate running processes
2. Analyze parent–child relationships
3. Audit Windows services
4. Compare with baseline
5. Detect suspicious behavior
6. Generate alerts
7. Generate final report

---

## 📊 Output

* Alerts displayed in terminal
* Report generated after execution

### Example Output

```
[HIGH] Suspicious Process: winword.exe → powershell.exe
[HIGH] Unauthorized Process: unknown.exe

WINDOWS SECURITY MONITORING REPORT
----------------------------------------
Total Running Processes: 120
Total Alerts Generated: 5
```

---

## 📁 Project Structure

```
windows-process-monitor/
│── main.py
│── reports/
|   |── final_report.txt
|
│── logs/
|    |── alerts.log
|    |── alerts.txt
|
│── process_monitor.py
│── detector.py
│── service_audit.py
│── service_collector.py
│── service_detector.py
│── baseline_generator.py
│── report_generator.py
│── test_services.py
│── README.md
```

---

## ✅ Advantages

* Behavior-based detection
* Detects persistence techniques
* Lightweight and modular design
* Easy to extend
* Useful for SOC learning

---

## ⚠️ Limitations

* No kernel-level monitoring
* No network traffic analysis
* Rule-based (limited against new attacks)
* Cannot fully detect fileless malware

---

## 🚀 Future Improvements

* Network monitoring
* Registry monitoring
* Automated response (kill process/service)
* Digital signature verification
* Machine learning-based detection
* SIEM integration

---

## 📚 Learning Outcomes

* Understanding Windows processes & services
* Behavioral threat detection
* Python system monitoring
* Alert and report generation
* SOC-level monitoring concepts

---

## 🏁 Conclusion

This project demonstrates how behavior-based monitoring can detect suspicious activity in Windows systems. It provides practical exposure to real-world cybersecurity techniques used in endpoint detection and response systems.

---

## 📦 Deliverables

* Python scripts
* Monitoring reports
* Alert logs
* Documentation
* Screenshots

---

## 👩‍💻 Author

**Vaishali Vasant Kadam**
Cyber Security Internship Project
📅 2026

---

⭐ *If you like this project, consider giving it a star!*
