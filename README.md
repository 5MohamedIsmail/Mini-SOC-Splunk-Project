# Mini SOC - Splunk Enterprise Project

Hands‑on blue team project demonstrating a **Mini Security Operations Center (SOC)** built with **Splunk Enterprise** as the SIEM layer. The focus is on real SOC workflows: log collection, Windows auditing, detection engineering, alerting, and dashboarding.

![Dashboard Preview](screenshots/05-dashboard/full-dashboard.png)

## Overview

This repository captures a compact but realistic SOC lab built to practice hands‑on detection engineering with Splunk. The goal was not just to install Splunk, but to enrich Windows logging, write custom SPL detections, tune alerts, and summarize findings in a simple dashboard.

It’s designed to be both:
- A **portfolio showcase** for hiring managers and recruiters.
- A **technical reference** for anyone interested in practical Splunk‑based detections.

## Project Goals

- Set up a functional Mini SOC using Splunk Enterprise 9.4
- Forward Windows event logs via Splunk Universal Forwarder
- Configure Windows advanced auditing for stronger telemetry
- Write, test, and tune custom detections using SPL
- Configure alerts for suspicious activity
- Build an executive‑style dashboard for SOC visibility

## Lab Architecture

The lab consists of:
- **Splunk Enterprise 9.4** as the SIEM platform
- **Windows endpoint(s)** with advanced auditing enabled
- **Splunk Universal Forwarder** forwarding events into Splunk
- Detection logic mapped to **MITRE ATT&CK** techniques

> See the `screenshots/01-architecture/` folder for setup visuals.

## Detection Catalog

| Use Case | MITRE ATT&CK | Event IDs / Signals | Status |
|---|---|---|---|
| Scheduled Task Persistence | T1053 | 4688, 4698 | ✅ Implemented |
| Brute Force Detection | T1110 | 4625 | ✅ Implemented |
| Suspicious PowerShell | T1059.001 | PowerShell cmdline patterns | ✅ Implemented |

## Implemented Use Cases

### 1) Scheduled Task Persistence (T1053)
Detects persistence attempts using `schtasks.exe` and new scheduled task creation.

- Watches **Event ID 4688** for suspicious process creation involving `schtasks.exe`.
- Correlates with **Event ID 4698** for task creation activity.
- Focuses on persistence‑style task names, unusual paths, and suspicious parent‑child relationships.

**Why it matters:** Scheduled tasks are a common attacker persistence vector, and handling them cleanly is a solid entry‑level SOC skill.

**Artifacts:**
- Screenshot: `screenshots/02-scheduled-task/`
- SPL: `detections/scheduled-task-persistence.spl`

### 2) Brute Force Attack Detection (T1110)
Detects repeated failed authentication attempts that may indicate password guessing or brute force activity.

- Monitors **Event ID 4625** for failed logons.
- Groups failures by host, user, or source IP over a short time window.
- Triggers a **high‑severity alert** when a threshold is exceeded.

**Why it matters:** Brute force detection is a foundational SOC use case and demonstrates threshold‑based alerting, tuning, and false‑positive management.

**Artifacts:**
- Screenshot: `screenshots/03-brute-force/`
- SPL: `detections/brute-force-detection.spl`

### 3) Suspicious Obfuscated PowerShell (T1059.001)
Detects potentially malicious PowerShell usage with obfuscation or stealth‑focused flags.

- Watches command‑line indicators such as:
  - `-enc` / `-EncodedCommand`
  - `-w hidden`
  - `IEX`
  - other suspicious execution patterns
- Uses process creation visibility to inspect parent process, command line, and execution context.

**Why it matters:** PowerShell abuse is a very common attacker pattern, so this detection is both practical and relevant for real‑world SOC work.

**Artifacts:**
- Screenshot: `screenshots/04-powershell-obfuscation/`
- SPL: `detections/powershell-obfuscation.spl`

## Example SPL Queries

### Scheduled Task Detection
```spl
index=* (EventCode=4688 OR EventCode=4698)
| search CommandLine="*schtasks*" OR TaskName="*"
| stats count values(CommandLine) values(TaskName) by host user EventCode
```

### Brute Force Detection
```spl
index=* EventCode=4625
| bin _time span=5m
| stats count by _time, host, Account_Name, Source_Network_Address
| where count >= 5
```

### Suspicious PowerShell Detection
```spl
index=* EventCode=4688
| search CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-w hidden*" OR CommandLine="*IEX*"
| table _time host user ParentProcessName NewProcessName CommandLine
```

> Full SPL queries are in the `detections/` folder.

## Dashboard and Alerts

The project includes custom alerts and an executive dashboard to translate raw detections into something more operational.

**Dashboard highlights:**
- Detection visibility across the three main use cases.
- Alert summaries for suspicious activity.
- SOC‑style layout for quick review and demonstration.

**Alerting focus:**
- Threshold‑based brute force alerts.
- Detection‑driven alerts for persistence and suspicious PowerShell.
- Tuning to reduce false positives while keeping alerts meaningful.

## Screenshots

### Scheduled Task Detection
![Scheduled Task Detection](screenshots/02-scheduled-task/schtasks-detection.png)

### Brute Force Alert
![Brute Force Alert](screenshots/03-brute-force/brute-force-alert.png)

### Executive Dashboard
![Executive Dashboard](screenshots/05-dashboard/full-dashboard.png)

Additional screenshots are in the `screenshots/` folder.

## Technologies and Skills

- Splunk Enterprise 9.4
- Splunk Universal Forwarder
- SPL (Search Processing Language)
- Windows Event Logs
- Windows Advanced Audit Policy configuration
- Detection engineering fundamentals
- Alert creation and tuning
- MITRE ATT&CK mapping
- Dashboard development

## Lessons Learned

- **Command‑line auditing is critical.** Process creation logging adds major detection value for tools like `schtasks.exe` and PowerShell.
- **Tuning matters.** Detections must be sensitive enough to catch real activity without flooding the analyst with false positives.
- **Correlation improves context.** Combining multiple event types often produces stronger signals than single‑event rules.
- **Performance needs attention.** Several scheduled searches require careful design to avoid overloading the Splunk instance.
- **Presentation matters.** A simple but clear dashboard helps make SOC‑style work more tangible and understandable.

## Repository Structure

```text
Splunk-Mini-SOC/
├── README.md
├── screenshots/
│   ├── 01-architecture/
│   ├── 02-scheduled-task/
│   ├── 03-brute-force/
│   ├── 04-powershell-obfuscation/
│   ├── 05-dashboard/
│   └── alerts/
├── detections/
│   ├── scheduled-task-persistence.spl
│   ├── brute-force-detection.spl
│   ├── powershell-obfuscation.spl
├── configs/
│   ├── inputs.conf
│   ├── props.conf
│   └── audit-policy-notes.md
└── docs/
    └── project-report.pdf
```

> Folders can be added incrementally as needed.

## How to Explore

1. Read this README to understand the scope and goals.
2. Browse the screenshots for visual proof of the lab and detections.
3. Inspect the SPL files in `detections/` for detection logic.
4. Optionally review configuration notes in `configs/` if you want more detail.

## Notes

- This is a **portfolio / showcase project**, not a production deployment.
- The environment is intentionally compact and focused on core SOC workflows.
- Any sensitive data has been sanitized before publication.

## Author

**Mohamed Ismail**  
Mini SOC / Splunk Enterprise Project  
May 2026
