# 🛡️ Microsoft Sentinel SOC Home Lab

**Conceptual SOC monitoring environment design using Microsoft Sentinel and Azure — academic research and lab study**

---

## Overview

This project documents my research and study of Microsoft Sentinel as a cloud-native SIEM platform. Through academic coursework and guided lab exercises, I explored how enterprise SOC environments are architected, how detection rules are engineered, and how incident response workflows operate at tier-1 and tier-2 levels.

---

## Architecture Studied

- **Cloud Provider:** Microsoft Azure
- **SIEM:** Microsoft Sentinel
- **Log Sources:** Windows VMs (Security Event Logs), Azure Activity Logs
- **Data Connectors:** Windows Security Events via AMA, Azure Activity

---

## What Was Studied & Designed

### Infrastructure Design
- Studied how Windows VMs are provisioned in Azure as log sources
- Researched centralized log ingestion pipeline configuration into Microsoft Sentinel
- Reviewed data connector setup for structured event ingestion

### Detection Engineering
Researched and designed KQL analytic rules targeting:
- **Failed authentication bursts** — detecting brute-force login patterns
- **Off-hours logins** — alerting on access outside business hours
- **Privilege escalation activity** — monitoring for suspicious role/group changes

### Dashboards & Visualization
- Studied Sentinel workbook design for visualizing security event trends
- Researched alert volume mapping by severity, source, and time window

### Incident Response Workflows
- Studied end-to-end IR workflow: alert triage → investigation → timeline reconstruction → remediation documentation
- Researched tier-1 and tier-2 SOC analyst handoff procedures

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

## Skills Demonstrated

`Microsoft Sentinel` `KQL` `Azure` `SIEM Engineering` `Detection Rules` `Incident Response` `Log Analysis` `Threat Detection`

---

## Frameworks Referenced

- MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts), T1078.004 (Cloud Accounts)
- NIST CSF 2.0: Detect (DE.AE), Respond (RS.AN)
