# 🛡️ Microsoft Sentinel SOC Home Lab

**Academic project — SOC monitoring environment using Microsoft Sentinel as part of MS Cybersecurity coursework at University of Central Missouri**

---

## Overview

This project was completed as part of my MS Cybersecurity program at the University of Central Missouri. I designed and deployed a cloud-based SOC monitoring environment using Microsoft Sentinel in Azure, built KQL detection rules targeting real attack patterns, and practiced end-to-end incident response workflows simulating tier-1 and tier-2 SOC analyst operations.

---

## Academic Context

- **Institution:** University of Central Missouri
- **Program:** MS Cybersecurity
- **Focus:** SIEM engineering, cloud security, incident response

---

## Architecture

- **Cloud Provider:** Microsoft Azure
- **SIEM:** Microsoft Sentinel
- **Log Sources:** Windows VMs (Security Event Logs), Azure Activity Logs
- **Data Connectors:** Windows Security Events via AMA, Azure Activity

---

## What Was Done

### Infrastructure
- Provisioned Windows VMs in Azure as log sources
- Configured Sentinel workspace with centralized log ingestion pipeline
- Set up data connectors for structured event ingestion

### Detection Engineering
Built custom KQL analytic rules targeting:
- **Failed authentication bursts** — detecting brute-force login patterns
- **Off-hours logins** — alerting on access outside business hours
- **Privilege escalation activity** — monitoring for suspicious role/group changes

### Dashboards & Visualization
- Built Sentinel workbooks to visualize security event trends over time
- Mapped alert volume by severity, source, and time window

### Incident Response Simulation
- Practiced full IR workflow: alert triage → investigation → timeline reconstruction → remediation documentation
- Simulated tier-1 and tier-2 analyst handoff scenarios

---

## KQL Queries Developed

**Failed authentication burst detection:**

    SecurityEvent
    | where EventID == 4625
    | summarize FailCount = count() by Account, IpAddress, bin(TimeGenerated, 5m)
    | where FailCount > 10
    | order by FailCount desc

**Off-hours login detection:**

    SigninLogs
    | where TimeGenerated between (datetime(00:00) .. datetime(06:00))
    | where ResultType == 0
    | project TimeGenerated, UserPrincipalName, IPAddress, Location

---

## What I Learned

- How to architect a cloud-based SOC environment from scratch in Azure
- How KQL detection logic translates real attack patterns into actionable alerts
- How Sentinel workbooks help visualize and prioritize security events
- How tier-1 and tier-2 SOC analysts triage and investigate incidents

---

## Frameworks Referenced

- MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts), T1078.004 (Cloud Accounts)
- NIST CSF 2.0: Detect (DE.AE), Respond (RS.AN)

---

## Skills Demonstrated

`Microsoft Sentinel` `KQL` `Azure` `SIEM Engineering` `Detection Rules` `Incident Response` `Log Analysis` `Threat Detection`
