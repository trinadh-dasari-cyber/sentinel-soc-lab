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

```kql
