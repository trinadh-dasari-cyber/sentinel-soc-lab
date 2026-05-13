# 🛡️ Microsoft Sentinel SOC Home Lab

**A fully operational Security Operations Center (SOC) environment built in Microsoft Azure**

---

## Overview

This project involved designing and deploying a cloud-based SOC monitoring environment from scratch using Microsoft Sentinel. The goal was to simulate real-world tier-1 and tier-2 SOC analyst workflows — from log ingestion through detection, alerting, and incident response documentation.

---

## Architecture

- **Cloud Provider:** Microsoft Azure
- **SIEM:** Microsoft Sentinel
- **Log Sources:** Windows VMs (Security Event Logs), Azure Activity Logs
- **Data Connectors:** Windows Security Events via AMA, Azure Activity

---

## What Was Built

### Infrastructure
- Provisioned Windows VMs in Azure as log sources
- Configured Sentinel workspace with centralized log ingestion pipeline
- Set up data connectors for structured event ingestion

### Detection Engineering
Custom KQL analytic rules built for:
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

## Key KQL Queries

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

## Skills Demonstrated

`Microsoft Sentinel` `KQL` `Azure` `SIEM Engineering` `Detection Rules` `Incident Response` `Log Analysis` `Threat Detection`

---

## Frameworks Referenced

- MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts), T1078.004 (Cloud Accounts)
- NIST CSF 2.0: Detect (DE.AE), Respond (RS.AN)
