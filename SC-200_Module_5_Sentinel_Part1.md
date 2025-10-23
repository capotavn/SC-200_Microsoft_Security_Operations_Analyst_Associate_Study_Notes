# SC-200 Study Notes - Module 5: Microsoft Sentinel (Part 1)
## 🛡️ Cloud-Native SIEM/SOAR Solution - Foundation & Configuration

**Exam Weight:** This content supports ~40-45% of the SC-200 exam (LARGEST MODULE!)
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest Sentinel Updates (July-Oct 2025)

---

## 🎯 SC-200 Exam Objectives Covered in This Module

### **From "Configure security operations infrastructure" (10-15%)**
- ✅ Configure and manage Microsoft Sentinel workspaces
- ✅ Configure and use Microsoft connectors for Azure resources
- ✅ Plan and configure Syslog and Common Event Format (CEF) event collections
- ✅ Plan and configure collection of Windows Security events using data collection rules
- ✅ Configure threat intelligence connectors (TAXII, STIX, MISP)
- ✅ Create custom log tables in the workspace

### **From "Configure detections" (20-25%)**
- ✅ Configure scheduled query rules (KQL)
- ✅ Configure near-real-time (NRT) query rules
- ✅ Configure anomaly detection analytics rules
- ✅ Configure the Fusion rule
- ✅ Manage analytics rules from Content hub
- ✅ Query Microsoft Sentinel data using ASIM parsers

### **From "Manage incident response" (25-30%)**
- ✅ Triage, assign, and investigate incidents in Microsoft Sentinel
- ✅ Create and configure Microsoft Sentinel playbooks
- ✅ Configure analytic rules to trigger automation
- ✅ Run playbooks on on-premises resources

### **From "Perform threat hunting" (15-20%)**
- ✅ Identify threats using KQL
- ✅ Create custom hunting queries
- ✅ Use hunting bookmarks for investigations
- ✅ Monitor hunting queries using Livestream
- ✅ Retrieve and manage archived log data

### **Cross-Module Integration:**
- ✅ Bidirectional synchronization with Microsoft Defender XDR
- ✅ Integration with Microsoft Purview, Entra ID
- ✅ Unified security operations (Defender portal)

---

## 📚 Table of Contents - Part 1 (Sections 1-8)

1. [Microsoft Sentinel Overview](#1-microsoft-sentinel-overview)
2. [Architecture and Components](#2-architecture-and-components)
3. [Workspace Configuration](#3-workspace-configuration)
4. [Data Connectors](#4-data-connectors)
5. [Data Collection Rules (DCR)](#5-data-collection-rules-dcr)
6. [Custom Log Tables](#6-custom-log-tables)
7. [Threat Intelligence Integration](#7-threat-intelligence-integration)
8. [Cost Optimization](#8-cost-optimization)

**Part 2 will cover:** Analytics Rules, Incidents, Automation, Threat Hunting, Workbooks, Advanced Topics

---

## 1. Microsoft Sentinel Overview

### 1.1 What is Microsoft Sentinel?

**Microsoft Sentinel** is a **cloud-native SIEM (Security Information and Event Management)** and **SOAR (Security Orchestration, Automation, and Response)** solution that provides:

- **Intelligent security analytics** at cloud scale
- **Threat detection** across the entire enterprise
- **Automated threat response** and remediation
- **Proactive threat hunting** capabilities
- **Investigation** with AI and machine learning

**Why Microsoft Sentinel?**

```
Traditional SIEM Problems:
❌ Expensive on-premises infrastructure
❌ Complex to deploy and maintain
❌ Limited scalability (TB/day limits)
❌ Slow query performance on large datasets
❌ Manual correlation and investigation
❌ Difficult to integrate with cloud services

Microsoft Sentinel Solutions:
✅ Cloud-native (infinite scale, no infrastructure)
✅ Pay-as-you-go pricing (cost-effective)
✅ Built on Azure Monitor Logs (proven platform)
✅ AI/ML for threat detection (reduce false positives)
✅ Automated response (playbooks with Logic Apps)
✅ Native integration (Microsoft 365, Azure, third-party)
✅ KQL for powerful queries (flexible, fast)
```

### 1.2 SIEM vs SOAR

**Understanding the Difference:**

```
SIEM (Security Information and Event Management):
└─ Collect: Aggregate logs from all sources
└─ Detect: Analyze logs to identify threats
└─ Alert: Notify security team of suspicious activity
└─ Investigate: Provide tools to analyze incidents
└─ Report: Compliance reporting and dashboards

SOAR (Security Orchestration, Automation, and Response):
└─ Orchestrate: Coordinate multiple security tools
└─ Automate: Execute response actions without human intervention
└─ Respond: Remediate threats automatically
└─ Playbook: Predefined workflows for common scenarios
└─ Integration: Connect with IT/Security tools (ticketing, EDR, firewalls)

Microsoft Sentinel = SIEM + SOAR Combined:
├─ Logs ingested → Sentinel workspace (Log Analytics)
├─ Analytics rules → Detect threats (scheduled, NRT, anomaly, fusion)
├─ Incidents → Unified view of alerts
├─ Investigation → Entity mapping, timeline, graph
├─ Playbooks → Automated response (Logic Apps)
└─ Threat hunting → Proactive search for threats (KQL queries)
```

### 1.3 Key Capabilities

**Core Features:**

```
1️⃣ Data Collection (Ingestion)
   ├─ 100+ built-in connectors (Microsoft, third-party, custom)
   ├─ Collect from: Azure, On-premises, Multi-cloud, SaaS
   ├─ Support: Syslog, CEF, REST API, agents, Azure services
   └─ Scale: Petabytes of data per day

2️⃣ Threat Detection (Analytics)
   ├─ Scheduled rules: Run KQL queries on schedule (every 5 min - 14 days)
   ├─ Near-real-time (NRT) rules: Sub-minute detection (1-10 min latency)
   ├─ Anomaly detection: ML-based behavioral analytics
   ├─ Fusion: Multi-stage attack detection (correlates signals)
   └─ Microsoft Security alerts: Import from Defender XDR, Defender for Cloud

3️⃣ Incident Management
   ├─ Unified incidents: Group related alerts
   ├─ Triage: Assign, prioritize, investigate
   ├─ Entity mapping: Link users, IPs, hosts, files, URLs
   ├─ Timeline: Chronological view of events
   └─ Investigation graph: Visual relationship mapping

4️⃣ Automation (SOAR)
   ├─ Playbooks: Logic Apps workflows (automated response)
   ├─ Automation rules: Trigger playbooks on incident creation/update
   ├─ Actions: Isolate host, block IP, disable user, send email, create ticket
   └─ Integration: ServiceNow, Jira, Teams, Slack, PagerDuty, etc.

5️⃣ Threat Hunting
   ├─ Hunting queries: Built-in and custom KQL queries
   ├─ Bookmarks: Save interesting findings
   ├─ Livestream: Real-time query execution
   ├─ Notebooks: Jupyter notebooks for advanced analysis
   └─ MITRE ATT&CK: Map queries to attack techniques

6️⃣ UEBA (User and Entity Behavior Analytics)
   ├─ Baseline: Learn normal behavior (users, devices, apps)
   ├─ Anomalies: Detect deviations from baseline
   ├─ Risk scores: Assign risk scores to entities
   └─ Peer analysis: Compare user behavior to peers

7️⃣ Threat Intelligence
   ├─ 🆕 ThreatIntelIndicators table (STIX 2.1 support)
   ├─ 🆕 ThreatIntelObjects table (relationships, threat actors)
   ├─ Connectors: TAXII, STIX, MISP, upload API, Microsoft Defender TI
   ├─ 🆕 Bi-directional sharing: Export TI back to platforms
   └─ Enrichment: Correlate IoCs with logs (IPs, domains, file hashes)

8️⃣ Visualization and Reporting
   ├─ Workbooks: Interactive dashboards (Azure Monitor Workbooks)
   ├─ Built-in workbooks: 100+ templates from Content hub
   ├─ Custom workbooks: Create tailored views
   └─ Export: PDF, Excel for reporting
```

### 1.4 Integration with Microsoft Ecosystem

**Unified Security Operations:**

```
Microsoft Sentinel Integration Points:

🔷 Microsoft Defender XDR (Unified SOC)
   ├─ Bidirectional sync: Incidents, alerts, entities
   ├─ Unified portal: security.microsoft.com (Defender portal)
   ├─ Advanced Hunting: Query Sentinel data from Defender portal
   ├─ 🆕 July 2025: Automatic onboarding for new customers
   └─ 🆕 July 2026: Azure portal Sentinel retired (Defender only)

🔷 Microsoft Entra ID (Azure AD)
   ├─ Sign-in logs: Monitor authentication events
   ├─ Audit logs: Track directory changes
   ├─ Identity Protection: Risk detections
   └─ Conditional Access: Policy enforcement logs

🔷 Microsoft Defender for Cloud
   ├─ Security alerts: Import alerts into Sentinel
   ├─ Recommendations: Track security posture
   ├─ Compliance: Regulatory compliance data
   └─ Workload protection: VM, SQL, containers, etc.

🔷 Microsoft Defender for Endpoint (MDE)
   ├─ Device logs: Process, network, file events
   ├─ Advanced Hunting: DeviceEvents tables
   ├─ Automated response: Isolate devices via playbooks
   └─ Threat intelligence: File hashes, IPs from MDE

🔷 Microsoft Defender for Office 365 (MDO)
   ├─ Email logs: Sent, received, filtered emails
   ├─ Phishing: Reported phishing attempts
   ├─ Malware: Detected malware in emails
   └─ Safe Links/Attachments: Click logs, detonation results

🔷 Microsoft Defender for Cloud Apps (MDCA)
   ├─ Cloud app activities: Sign-ins, file access, sharing
   ├─ Shadow IT: Cloud Discovery data
   ├─ OAuth apps: High-risk app detections
   └─ DLP: Data loss prevention alerts

🔷 Microsoft Purview
   ├─ DLP alerts: Data leakage incidents
   ├─ Information Protection: Sensitivity label usage
   ├─ Insider Risk: High-risk user activities
   └─ eDiscovery: Legal hold and investigation data

🔷 🆕 Microsoft Security Copilot (2025)
   ├─ Natural language investigation: "Summarize this incident"
   ├─ Guided response: AI-recommended remediation steps
   ├─ Incident summarization: Auto-generate incident reports
   └─ KQL assistance: Generate queries from natural language
```

### 1.5 Licensing and Pricing

**Licensing Options:**

```
Microsoft Sentinel Licensing:

1. Pay-As-You-Go (Most Common)
   ├─ Pricing: Per GB of data ingested
   ├─ Tiers:
   │  ├─ Pay-As-You-Go: $2.46/GB (first 5 GB/day free)
   │  ├─ Commitment Tiers: Volume discounts
   │  │  ├─ 100 GB/day: ~$1.20/GB (51% discount)
   │  │  ├─ 200 GB/day: ~$1.10/GB (55% discount)
   │  │  └─ Up to 5,000 GB/day: Scaling discounts
   │  └─ 🆕 Sentinel Data Lake (Preview - July 2025):
   │     ├─ Cost-effective long-term retention
   │     ├─ Lower cost per GB for archived data
   │     └─ Multi-modal analytics support
   │
   ├─ Additional costs:
   │  ├─ Log Analytics workspace: Same as Sentinel (included)
   │  ├─ Data retention: 90 days free, $0.10/GB/month after
   │  ├─ Playbooks (Logic Apps): Per execution (~$0.000025/action)
   │  └─ Notebooks (Azure ML): Compute costs (if used)

2. Microsoft 365 E5 / E5 Security (Bundled)
   ├─ Includes: 5 GB/day of Sentinel ingestion per user
   ├─ Eligible logs: Microsoft 365 logs only (Entra ID, Office 365)
   ├─ Additional logs: Pay-as-you-go pricing applies
   └─ Note: Only for Microsoft 365 data, not third-party logs

3. Microsoft Defender for Servers (Plan 2)
   ├─ Includes: 500 MB/day of Sentinel ingestion per server
   ├─ Eligible logs: Security events from Windows/Linux servers
   └─ Additional logs: Pay-as-you-go pricing

Cost Optimization Tips:
✅ Use commitment tiers (if ingesting >100 GB/day)
✅ 🆕 Migrate cold data to Sentinel Data Lake (lower cost)
✅ Filter logs at source (don't ingest unnecessary data)
✅ Use Basic Logs (lower cost, reduced query capabilities)
✅ Archive old logs (long-term retention at lower cost)
✅ Monitor usage with Azure Cost Management
```

**🆕 July 2025: Microsoft Defender Threat Intelligence (MDTI) Free**

```
MAJOR UPDATE - Free Threat Intelligence:

What Changed:
- Microsoft Defender Threat Intelligence (MDTI) was previously ~$10K+/year
- 🆕 Now FREE for all Sentinel + Defender XDR customers
- Convergence into Sentinel & Defender XDR (no separate purchase)

What You Get (Free):
├─ 84 trillion daily signals from Microsoft
├─ 10,000+ security professionals' analysis
├─ Finished threat intelligence:
│  ├─ Threat actor profiles
│  ├─ Threat tooling analysis
│  ├─ Vulnerability insights
│  └─ IOC (Indicator of Compromise) feeds
│
├─ Real-time updates: IOCs updated as threats evolve
├─ Integration: Direct correlation with incidents/assets
└─ Timeline: Full rollout by H1 2026, Phase 1 by October 2025

Impact on Exam:
- Understand MDTI is now included (not separate product)
- Know ThreatIntelIndicators and ThreatIntelObjects tables
- Recognize free vs paid threat intelligence sources
```

### 1.6 Use Cases

**Common Sentinel Deployment Scenarios:**

```
Scenario 1: Hybrid Cloud Security Monitoring
├─ Challenge: Monitor both Azure and on-premises resources
├─ Solution:
│  ├─ Deploy agents: Windows/Linux machines (on-prem + Azure)
│  ├─ Connect Azure services: Entra ID, Activity Log, NSG Flow Logs
│  ├─ Collect firewall logs: Syslog/CEF from Palo Alto, Cisco
│  └─ Analytics: Detect threats across hybrid environment
├─ Result: Unified visibility, single pane of glass

Scenario 2: Multi-Cloud SIEM (Azure + AWS + GCP)
├─ Challenge: Security monitoring across multiple clouds
├─ Solution:
│  ├─ AWS CloudTrail → Sentinel (S3 connector)
│  ├─ GCP Audit Logs → Sentinel (Pub/Sub connector)
│  ├─ Azure Activity Log → Sentinel (native connector)
│  └─ Analytics: Correlate threats across clouds
├─ Result: Comprehensive multi-cloud threat detection

Scenario 3: Compliance and Auditing (GDPR, HIPAA, PCI-DSS)
├─ Challenge: Meet regulatory requirements, audit trails
├─ Solution:
│  ├─ Ingest compliance-relevant logs (sign-ins, database access, file access)
│  ├─ Workbooks: Compliance dashboards (GDPR data access, HIPAA audit)
│  ├─ Retention: Configure long-term retention (7+ years)
│  └─ Reports: Generate audit reports for auditors
├─ Result: Compliance achieved, audit-ready

Scenario 4: SOC Automation (Reduce Manual Work)
├─ Challenge: SOC team overwhelmed with alerts, slow response
├─ Solution:
│  ├─ Automation rules: Auto-assign incidents to analysts
│  ├─ Playbooks: Auto-remediate (block IP, disable user, isolate device)
│  ├─ SOAR integrations: Create ServiceNow tickets, send Teams messages
│  └─ Reduce alert fatigue: Tune analytics rules, suppress false positives
├─ Result: 80% reduction in manual work, faster MTTR

Scenario 5: Advanced Threat Hunting
├─ Challenge: Proactively find threats not detected by rules
├─ Solution:
│  ├─ Hunting queries: Run custom KQL queries (MITRE ATT&CK mapped)
│  ├─ Bookmarks: Save interesting findings
│  ├─ Livestream: Monitor real-time activity
│  ├─ Notebooks: Advanced analysis with Python/ML
│  └─ Convert to rules: Operationalize successful hunts
├─ Result: Discover hidden threats, advanced persistent threats (APTs)
```

**🎯 Exam Tip:**
- **Microsoft Sentinel** = Cloud-native **SIEM + SOAR** (single solution)
- **SIEM**: Collect logs, detect threats, investigate
- **SOAR**: Automate response, orchestrate tools, playbooks
- **Key differentiator**: Cloud-native (no infrastructure), AI/ML, pay-as-you-go
- **Licensing**: Pay-per-GB, commitment tiers, bundled with E5/Defender for Servers
- 🆕 **July 2025**: MDTI now free, Sentinel Data Lake (cost-effective), automatic Defender portal onboarding
- 🆕 **July 2026**: Azure portal Sentinel will be retired (Defender portal only)
- **Primary use cases**: Hybrid/multi-cloud monitoring, compliance, SOC automation, threat hunting

---

## 2. Architecture and Components

### 2.1 High-Level Architecture

**Microsoft Sentinel Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                      Data Sources                            │
├─────────────────────────────────────────────────────────────┤
│  Azure Services  │  On-Premises  │  SaaS Apps  │  Multi-Cloud│
│  ├─ Entra ID     │  ├─ Windows   │  ├─ Office  │  ├─ AWS     │
│  ├─ Activity Log │  ├─ Linux     │  ├─ GitHub  │  └─ GCP     │
│  ├─ NSG Logs     │  ├─ Firewalls │  └─ Okta    │             │
│  └─ Defender XDR │  └─ Syslog    │             │             │
└─────────────────────────────────────────────────────────────┘
                          ↓ (Data Connectors)
┌─────────────────────────────────────────────────────────────┐
│              Microsoft Sentinel Workspace                    │
│             (Built on Log Analytics Workspace)               │
├─────────────────────────────────────────────────────────────┤
│  📊 Data Ingestion Layer                                    │
│  ├─ Log Analytics Agent (AMA - Azure Monitor Agent)        │
│  ├─ REST API (HTTP Data Collector)                         │
│  ├─ Syslog/CEF forwarder                                   │
│  ├─ Native connectors (Azure Diagnostic Settings)          │
│  └─ 🆕 Sentinel Data Lake (cost-effective storage)         │
│                                                             │
│  💾 Data Storage                                            │
│  ├─ Raw logs (ingested data)                               │
│  ├─ Parsed tables (SecurityEvent, Syslog, CommonSecurityLog)│
│  ├─ Custom tables (Custom logs, _CL suffix)                │
│  ├─ 🆕 ThreatIntelIndicators (STIX 2.1)                    │
│  ├─ 🆕 ThreatIntelObjects (relationships, threat actors)   │
│  └─ Retention: 90 days default, 730 days max               │
│                                                             │
│  🔍 Analytics Engine                                        │
│  ├─ Scheduled rules (KQL, 5 min - 14 days)                │
│  ├─ Near-real-time (NRT) rules (1-10 min latency)         │
│  ├─ Anomaly detection (ML-based)                           │
│  ├─ Fusion (multi-stage attack correlation)                │
│  └─ Microsoft Security (import from Defender, MDC)         │
│                                                             │
│  🎯 Incidents                                               │
│  ├─ Grouped alerts (related alerts → single incident)      │
│  ├─ Entity mapping (users, IPs, hosts, files, URLs)       │
│  ├─ Timeline (chronological event view)                    │
│  └─ Investigation graph (relationship visualization)       │
│                                                             │
│  🤖 Automation (SOAR)                                       │
│  ├─ Automation rules (incident-triggered)                  │
│  ├─ Playbooks (Logic Apps workflows)                       │
│  ├─ Response actions (block IP, disable user, isolate)    │
│  └─ Integrations (ServiceNow, Teams, Slack, PagerDuty)    │
│                                                             │
│  🔎 Threat Hunting                                          │
│  ├─ Hunting queries (built-in + custom KQL)               │
│  ├─ Bookmarks (saved findings)                             │
│  ├─ Livestream (real-time query execution)                │
│  ├─ Notebooks (Jupyter for advanced analysis)             │
│  └─ MITRE ATT&CK mapping                                   │
│                                                             │
│  📈 Visualization                                           │
│  ├─ Workbooks (Azure Monitor Workbooks)                   │
│  ├─ Built-in templates (100+ from Content hub)            │
│  └─ Custom dashboards (KQL-based)                         │
└─────────────────────────────────────────────────────────────┘
                          ↓ (Output/Integration)
┌─────────────────────────────────────────────────────────────┐
│                   External Systems                           │
├─────────────────────────────────────────────────────────────┤
│  ├─ Microsoft Defender XDR (unified incidents, bi-dir sync)│
│  ├─ ITSM: ServiceNow, Jira (ticket creation)              │
│  ├─ Communication: Teams, Slack, Email                     │
│  ├─ EDR: MDE, Carbon Black (isolate devices)              │
│  ├─ Firewalls: Palo Alto, Fortinet (block IPs)            │
│  └─ 🆕 TAXII servers (bi-directional TI sharing - 2025)    │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Core Components

**1. Log Analytics Workspace**

```
What: Foundation of Microsoft Sentinel (data storage and query engine)

Key Characteristics:
├─ Single workspace = Single Sentinel instance
├─ Data retention: 90 days free, up to 730 days (configurable)
├─ Query language: KQL (Kusto Query Language)
├─ Pricing: Pay-per-GB ingested (same as Sentinel)
├─ Location: Must be in supported Azure region
└─ Resource: Azure subscription-level resource

Workspace Structure:
Workspace
├─ Tables (pre-defined + custom)
│  ├─ SecurityEvent (Windows Security events)
│  ├─ Syslog (Linux syslog)
│  ├─ CommonSecurityLog (CEF logs)
│  ├─ SigninLogs (Entra ID sign-ins)
│  ├─ DeviceEvents (MDE device telemetry)
│  ├─ EmailEvents (MDO email logs)
│  ├─ CloudAppEvents (MDCA activities)
│  ├─ 🆕 ThreatIntelIndicators (STIX 2.1 indicators)
│  ├─ 🆕 ThreatIntelObjects (TI relationships)
│  └─ Custom_CL (custom log tables, _CL suffix)
│
├─ Functions (saved queries, parsers)
│  ├─ ASIM parsers (normalized schema)
│  └─ Custom functions
│
└─ Saved searches
   ├─ Hunting queries
   └─ Investigation queries

Workspace Limits:
├─ Ingestion: No hard limit (petabytes/day possible)
├─ Query: 10,000 records by default (configurable to millions)
├─ Retention: 730 days max in workspace, longer via archive
└─ Workspaces per subscription: 100 (soft limit, can increase)
```

**2. Data Connectors**

```
What: Pre-built integrations to ingest data into Sentinel

Connector Categories:

A. Service-to-Service (No Agent Required)
   ├─ Azure services: Entra ID, Activity Log, Defender for Cloud
   ├─ Microsoft 365: Office 365, Teams, Defender XDR
   ├─ SaaS apps: AWS, GitHub, Okta (REST API-based)
   └─ Setup: Azure Policy or manual configuration

B. Agent-Based (Requires Agent Installation)
   ├─ Windows/Linux machines: Azure Monitor Agent (AMA)
   ├─ Syslog: CEF/Syslog forwarder (Linux VM)
   └─ Custom: HTTP Data Collector API

C. Third-Party (REST API)
   ├─ Security vendors: Palo Alto, Cisco, Fortinet, CrowdStrike
   ├─ SIEM: Splunk, QRadar, ArcSight (migration scenarios)
   └─ Custom: Build custom connectors using Logic Apps

Connector Deployment:
├─ Content hub: Install solutions (includes connectors + analytics rules)
├─ Data connectors page: Enable built-in connectors
├─ Azure Policy: Auto-deploy connectors at scale
└─ API: Programmatic connector deployment

Popular Connectors (SC-200 Exam Focus):
1. Microsoft Entra ID (Azure AD)
2. Microsoft Defender XDR
3. Azure Activity (subscription-level events)
4. Windows Security Events (via AMA)
5. Syslog / CEF (firewalls, network devices)
6. Threat Intelligence (TAXII, STIX, upload API)
7. Office 365 (Exchange, SharePoint, Teams)
8. AWS (CloudTrail, VPC Flow Logs)
```

**3. Analytics Rules**

```
What: Detection logic that generates alerts when threats detected

Rule Types:

1️⃣ Scheduled Query Rules
   ├─ Runs: On schedule (5 min to 14 days)
   ├─ Logic: KQL query
   ├─ Output: Alert if query returns results
   ├─ Use: Most common rule type (custom detections)
   └─ Example: Detect brute force (>10 failed logins in 5 min)

2️⃣ Near-Real-Time (NRT) Rules
   ├─ Runs: Every 1 minute (sub-minute detection possible)
   ├─ Logic: KQL query (simplified, limited operators)
   ├─ Output: Alert within 1-10 minutes of event
   ├─ Use: Time-sensitive detections (break glass account use)
   └─ Limit: 50 NRT rules per workspace

3️⃣ Anomaly Detection Rules
   ├─ Runs: Continuously (ML-based)
   ├─ Logic: Machine learning models (baselines)
   ├─ Output: Alert on anomalies (deviation from normal)
   ├─ Use: Detect unknown threats, insider threats
   └─ Note: Built-in templates (Microsoft-provided)

4️⃣ Fusion Rules
   ├─ Runs: Continuously (correlation engine)
   ├─ Logic: Multi-stage attack detection (correlates multiple signals)
   ├─ Output: Incident (not just alert) - high fidelity
   ├─ Use: Detect advanced multi-stage attacks
   └─ Example: Phishing email → malware execution → data exfil

5️⃣ Microsoft Security Rules
   ├─ Runs: Real-time (import from external sources)
   ├─ Logic: Import alerts from Defender XDR, Defender for Cloud
   ├─ Output: Alert/incident in Sentinel
   ├─ Use: Unify alerts from Microsoft security products
   └─ Note: Bidirectional sync with Defender XDR

Rule Components:
├─ Query: KQL logic (what to detect)
├─ Entity mapping: Map results to entities (user, IP, host, etc.)
├─ Alert enrichment: Add context (geolocation, threat intel)
├─ Grouping: Group related alerts into single incident
├─ Suppression: Suppress duplicate alerts (time window)
├─ Automation: Trigger playbooks on alert creation
└─ MITRE ATT&CK: Map to attack techniques
```

**4. Incidents**

```
What: Grouped alerts representing a security event requiring investigation

Incident Structure:
Incident
├─ Title: "Suspicious PowerShell execution on DESKTOP-123"
├─ Severity: High (Informational, Low, Medium, High, Critical)
├─ Status: New, Active, Closed (benign, false positive, true positive)
├─ Owner: Assigned to analyst (or unassigned)
├─ Description: Auto-generated or custom
├─ Alerts: Multiple alerts grouped (or single alert)
├─ Entities: Users, IPs, hosts, files, URLs, processes
├─ Timeline: Chronological event view
├─ Evidence: Logs, files, network connections
├─ Comments: Analyst notes, investigation findings
└─ Tags: Custom labels (VIP user, confirmed breach, etc.)

Incident Lifecycle:
New (alert → incident created)
↓
Active (analyst investigating)
↓
Closed (resolved - benign, false positive, or true positive)

Incident Actions:
├─ Assign: Assign to analyst or team
├─ Change severity: Increase/decrease based on findings
├─ Add comments: Document investigation steps
├─ Run playbook: Execute automated response
├─ Create tasks: Break investigation into sub-tasks
└─ Close: Mark as resolved (benign, FP, TP)
```

**5. Playbooks (Logic Apps)**

```
What: Automated workflows triggered by incidents or manually

Playbook Architecture:
Trigger (Incident created/updated or manual)
↓
Actions (Sequence of steps)
├─ Get incident details (entities, severity, owner)
├─ Enrich: Query threat intel, WHOIS, geolocation
├─ Analyze: Check user risk score, device compliance
├─ Decision: If/else logic (severity = High?)
├─ Respond:
│  ├─ Block IP (firewall API)
│  ├─ Disable user (Entra ID)
│  ├─ Isolate device (MDE)
│  ├─ Send email (to analyst, manager)
│  ├─ Create ticket (ServiceNow, Jira)
│  └─ Post to Teams/Slack
└─ Update incident: Add comment, change status

Common Playbook Scenarios:
1. Enrich incident: Add geolocation, threat intel, WHOIS
2. Block IP: Add IP to firewall blocklist (Palo Alto, Azure Firewall)
3. Disable compromised account: Disable user in Entra ID, revoke sessions
4. Isolate infected device: Isolate via MDE API
5. Notify SOC: Send email/Teams message to on-call analyst
6. Create ticket: Auto-create ServiceNow/Jira ticket
7. Collect evidence: Export logs, take memory dump (forensics)

Playbook Integration:
├─ Microsoft: Entra ID, MDE, MDO, MDCA, Purview, Azure services
├─ Third-party: 1,000+ Logic Apps connectors
│  ├─ ITSM: ServiceNow, Jira, Zendesk
│  ├─ Communication: Teams, Slack, PagerDuty, Twilio
│  ├─ Security: Palo Alto, Fortinet, CrowdStrike, VirusTotal
│  ├─ Threat Intel: AlienVault OTX, ThreatConnect, MISP
│  └─ Cloud: AWS, GCP (cross-cloud response)
└─ Custom: HTTP requests, Azure Functions, webhooks
```

**6. Workbooks**

```
What: Interactive dashboards for visualization and reporting

Workbook Structure:
├─ Data source: Log Analytics workspace (KQL queries)
├─ Visualization: Charts, tables, maps, timelines
├─ Interactivity: Filters, parameters, drill-down
├─ Refresh: Manual or scheduled
└─ Export: PDF, Excel

Built-in Workbooks (Content hub):
├─ Azure Activity: Subscription-level activities
├─ Identity & Access: Sign-ins, authentication trends
├─ Office 365: Email, SharePoint, Teams usage
├─ Security Operations: Incidents, alerts, MTTR
├─ Threat Intelligence: IoC matches, threat actors
├─ UEBA: User risk scores, anomalies
└─ Compliance: GDPR, HIPAA, PCI-DSS dashboards

Custom Workbooks:
- Build from scratch using KQL queries
- Combine multiple data sources
- Tailored to specific use cases (executive reports, SOC metrics)
```

**🎯 Exam Tip:**
- **Log Analytics Workspace** = Foundation (data storage, KQL query engine)
- **Data Connectors** = Ingest logs (service-to-service, agent-based, API)
- **Analytics Rules**: Scheduled (most common), NRT (1-min), Anomaly (ML), Fusion (multi-stage), Microsoft Security (import)
- **Incidents** = Grouped alerts, investigation hub
- **Playbooks** = Logic Apps workflows (SOAR automation)
- **Workbooks** = Dashboards (visualization, reporting)
- 🆕 **2025 Updates**: ThreatIntelIndicators/Objects tables (STIX 2.1), Sentinel Data Lake, Defender portal integration

---

## 3. Workspace Configuration

### 3.1 Creating a Sentinel Workspace

**Deployment Steps:**

```
Prerequisites:
✅ Azure subscription (Owner or Contributor role)
✅ Log Analytics Workspace created (or create during deployment)
✅ Microsoft.SecurityInsights resource provider registered

Step 1: Create Log Analytics Workspace
───────────────────────────────────────
Azure Portal → Log Analytics workspaces → Create

Configuration:
├─ Subscription: Select Azure subscription
├─ Resource group: Create new or use existing
├─ Name: sentinel-workspace-prod (globally unique)
├─ Region: Choose Azure region (data residency)
│  ├─ Common: East US, West Europe, Southeast Asia
│  └─ Note: Choose region close to data sources (lower latency)
└─ Pricing tier:
   ├─ Pay-As-You-Go: $2.46/GB (first 5 GB/day free)
   └─ Commitment Tiers: 100 GB/day, 200 GB/day, etc.

Step 2: Enable Microsoft Sentinel
───────────────────────────────────────
Azure Portal → Microsoft Sentinel → Create

Configuration:
├─ Select Log Analytics workspace: sentinel-workspace-prod
├─ Review pricing: Confirm pricing tier
└─ Create: Enable Sentinel on workspace

Result: Sentinel enabled, ready to configure connectors

⚠️ Important Notes:
- Cannot enable Sentinel on workspace already used by Azure Security Center
- Workspace cannot be moved between regions after creation
- Workspace name must be unique within resource group
- 🆕 July 2025: New customers auto-onboarded to Defender portal
```

**🆕 July 2025: Automatic Defender Portal Onboarding**

```
What Changed:
- New Sentinel customers (first workspace onboarded on/after July 1, 2025)
- Automatically onboarded to Microsoft Defender portal
- No manual onboarding needed

Requirements for Auto-Onboarding:
✅ Subscription Owner or User Access Administrator role
✅ Not Azure Lighthouse-delegated user
✅ First Sentinel workspace in tenant

What Happens:
1. Create Sentinel workspace in Azure portal
2. Workspace automatically appears in Defender portal (security.microsoft.com)
3. Azure portal Sentinel shows redirect links to Defender portal
4. Users see unified experience (Sentinel + Defender XDR)

🆕 July 2026: Azure Portal Sentinel Retirement
- Azure portal Sentinel will be retired
- Defender portal only (automatic redirection)
- Plan transition now for existing customers

Implications for Exam:
- Know both portals (Azure + Defender) for now
- Understand auto-onboarding for new customers
- Recognize 2026 retirement timeline
```

### 3.2 Workspace Settings

**Key Configuration Options:**

```
Sentinel Settings (Azure Portal: Sentinel → Settings)

1️⃣ Workspace Settings
   ├─ Pricing tier: Pay-As-You-Go, Commitment tiers
   ├─ Data retention: 90 days (free), up to 730 days
   ├─ 🆕 Data Lake: Enable Sentinel Data Lake (preview)
   └─ Daily cap: Limit daily ingestion (prevent cost overruns)

2️⃣ Analytics Rule Insights
   ├─ Review rule effectiveness (alerts generated, incidents created)
   ├─ Identify noisy rules (high alert volume, low true positive rate)
   └─ Tuning recommendations (adjust thresholds, suppress)

3️⃣ Entity Behavior (UEBA)
   ├─ Enable: Turn on User and Entity Behavior Analytics
   ├─ Data sources: Select logs for UEBA (SigninLogs, SecurityEvent, etc.)
   ├─ Learning period: 30 days to establish baselines
   └─ Risk scoring: Assign risk scores to users, devices

4️⃣ Threat Intelligence
   ├─ Data sources: Connect TAXII, STIX, MISP, upload API
   ├─ 🆕 ThreatIntelIndicators table: STIX 2.1 support
   ├─ 🆕 ThreatIntelObjects table: Relationships, threat actors
   └─ 🆕 Bi-directional export: Export TI to external platforms

5️⃣ Automation
   ├─ Automation rules: Incident-triggered workflows
   ├─ Playbook permissions: Grant Sentinel managed identity access
   └─ Playbook templates: Install from Content hub

6️⃣ Audit and Health
   ├─ Audit logs: Track Sentinel configuration changes
   ├─ Health monitoring: Data connector status, ingestion issues
   └─ Diagnostic settings: Send Sentinel logs to storage/event hub
```

### 3.3 Data Retention and Archiving

**Retention Configuration:**

```
Retention Tiers:

1️⃣ Interactive (Hot) Tier
   ├─ Retention: 90 days (free), up to 730 days (paid)
   ├─ Cost: $0.10/GB/month after 90 days
   ├─ Query: Full KQL capabilities, fast performance
   └─ Use: Active investigations, recent logs

2️⃣ 🆕 Sentinel Data Lake (Preview - July 2025)
   ├─ Retention: Long-term, cost-effective
   ├─ Cost: Lower than hot tier (pricing TBD)
   ├─ Query: Multi-modal analytics, reduced KQL features
   ├─ Use: Cold data, compliance, historical analysis
   └─ Migration: Move old data from hot to data lake

3️⃣ Archive Tier (Long-term Storage)
   ├─ Retention: Up to 7+ years (compliance requirements)
   ├─ Cost: ~$0.02/GB/month (lowest cost)
   ├─ Query: Restore to hot tier first (time delay)
   ├─ Use: Regulatory compliance, rare access
   └─ Configuration: Set archive policy per table

Configuration:
────────────────
Azure Portal → Log Analytics workspace → Tables

Per-Table Retention:
├─ SecurityEvent: 365 days (1 year)
├─ SigninLogs: 180 days (6 months)
├─ Syslog: 90 days (default)
├─ Custom logs: 730 days (max for active investigations)
└─ Archive: Move to archive after X days

Example Configuration:
Table: SecurityEvent
├─ Interactive retention: 365 days
├─ Archive: After 365 days, move to archive
├─ Total retention: 7 years (compliance)
└─ Cost: Hot (365 days) + Archive (6+ years, much cheaper)

Restoring Archived Data:
1. Identify time range needed (specific dates)
2. Submit restore request (portal or API)
3. Wait for restoration (minutes to hours)
4. Query restored data (temporary table)
5. Data auto-deleted after retention period
```

### 3.4 Workspace Permissions (RBAC)

**Role-Based Access Control:**

```
Microsoft Sentinel Roles:

Built-in Roles:

1️⃣ Microsoft Sentinel Reader
   ├─ View: Data, incidents, workbooks, analytics rules
   ├─ Cannot: Create/edit rules, incidents, playbooks
   └─ Use: Junior analysts, read-only access

2️⃣ Microsoft Sentinel Responder
   ├─ View: All Sentinel data
   ├─ Manage: Incidents (assign, close, add comments)
   ├─ Cannot: Create/edit rules, playbooks
   └─ Use: SOC analysts (investigation, triage)

3️⃣ Microsoft Sentinel Contributor
   ├─ View: All Sentinel data
   ├─ Manage: Incidents, analytics rules, workbooks, playbooks
   ├─ Cannot: Delete workspace, change RBAC
   └─ Use: Senior analysts, threat hunters, SOC leads

4️⃣ Microsoft Sentinel Automation Contributor
   ├─ View: Sentinel data
   ├─ Manage: Playbooks, automation rules
   ├─ Use: Automation engineers, SOAR specialists
   └─ Note: Needed to attach playbooks to analytics rules

Additional Required Roles:

Log Analytics Reader (for KQL queries):
- Needed: Run queries in Log Analytics workspace
- Scope: Workspace or resource group level

Logic App Contributor (for playbooks):
- Needed: Create/edit playbooks (Logic Apps)
- Scope: Resource group containing Logic Apps

Custom Roles:
- Combine permissions for specific needs
- Example: "SOC Analyst" = Sentinel Responder + Log Analytics Reader

Best Practices:
✅ Principle of least privilege (minimum necessary access)
✅ Separate roles: Reader (view), Responder (investigate), Contributor (manage)
✅ Audit: Review permissions quarterly
✅ MFA: Require multi-factor authentication for Sentinel access
```

### 3.5 Multi-Workspace Architecture

**When to Use Multiple Workspaces:**

```
Scenarios:

1️⃣ Single Workspace (Most Common - Recommended)
   ├─ Pros: Centralized view, easier management, cost-effective
   ├─ Cons: Single point of failure, mixed data (if not properly filtered)
   └─ Use: Most organizations (single SOC, unified view)

2️⃣ Multiple Workspaces (Advanced Scenarios)
   ├─ Pros: Data isolation, separate billing, compliance (data residency)
   ├─ Cons: Complex management, higher cost, data correlation difficult
   └─ Use: Large enterprises, MSPs, strict data residency requirements

Reasons for Multiple Workspaces:

A. Data Residency (Compliance)
   ├─ Example: EU data must stay in EU, US data in US
   ├─ Solution: Workspace in EU region + Workspace in US region
   └─ Note: Cannot move workspace between regions

B. Separate Tenants (MSPs, Holding Companies)
   ├─ Example: MSP managing multiple customers
   ├─ Solution: One workspace per customer tenant
   └─ Note: Use Azure Lighthouse for cross-tenant management

C. Cost Allocation (Chargebacks)
   ├─ Example: IT department wants to charge business units
   ├─ Solution: Separate workspace per business unit
   └─ Note: Complex, usually better to use tags and cost allocation

D. Isolation (Security, Compliance)
   ├─ Example: Separate production from non-production logs
   ├─ Solution: Workspace for prod + workspace for dev/test
   └─ Note: Rare, usually not necessary

Cross-Workspace Queries:

Query multiple workspaces from single location:

```kql
union workspace("workspace1").SecurityEvent,
      workspace("workspace2").SecurityEvent
| where TimeGenerated > ago(24h)
| summarize count() by Computer
```

Limitations:
⚠️ Cannot query >100 workspaces in single query
⚠️ Performance degrades with many workspaces
⚠️ Cannot create cross-workspace analytics rules (workaround: Azure Lighthouse)
```

**🎯 Exam Tip:**
- **Workspace creation**: Log Analytics workspace first, then enable Sentinel
- 🆕 **Auto-onboarding** (July 2025): New customers auto-onboarded to Defender portal
- 🆕 **Portal retirement** (July 2026): Azure portal Sentinel retired, Defender only
- **Retention**: 90 days free, up to 730 days paid, 🆕 Data Lake (long-term, cost-effective), Archive (7+ years)
- **RBAC**: Reader (view), Responder (investigate), Contributor (manage), Automation Contributor (playbooks)
- **Multi-workspace**: Single workspace recommended, multiple for data residency/compliance
- **Cross-workspace queries**: Query multiple workspaces via KQL (union, workspace())

---

## 4. Data Connectors

### 4.1 Connector Overview

**Data Connector Categories:**

```
Microsoft Sentinel Data Connectors:

📊 Total: 100+ built-in connectors + unlimited custom

Categories:

1️⃣ Service-to-Service Connectors (No Agent)
   ├─ Azure native: Diagnostic settings, native integration
   ├─ Microsoft 365: Office 365, Defender XDR, MDCA, MDO
   ├─ SaaS apps: AWS, GCP, GitHub, Okta, Salesforce
   ├─ Setup: Enable via connector page or Azure Policy
   └─ Latency: Near real-time (1-5 minutes)

2️⃣ Agent-Based Connectors
   ├─ Windows/Linux: Azure Monitor Agent (AMA)
   ├─ Legacy: Log Analytics Agent (deprecated)
   ├─ Setup: Deploy agent to machines
   └─ Use: On-premises servers, Azure VMs, third-party VMs

3️⃣ Syslog / CEF Connectors
   ├─ Network devices: Firewalls, routers, switches
   ├─ Security appliances: Palo Alto, Cisco, Fortinet, Check Point
   ├─ Setup: Linux VM as syslog forwarder
   └─ Format: Syslog, Common Event Format (CEF)

4️⃣ API-Based Connectors (REST API)
   ├─ Third-party: Security vendors (CrowdStrike, Carbon Black)
   ├─ Custom: Build custom connectors via HTTP Data Collector API
   ├─ Setup: Logic Apps or custom code
   └─ Use: Any system with REST API

5️⃣ Solution-Based Connectors (Content hub)
   ├─ Packaged: Connector + analytics rules + workbooks + playbooks
   ├─ Install: One-click deployment from Content hub
   ├─ Vendors: 100+ security vendors (Palo Alto, Cisco, etc.)
   └─ Microsoft: Comprehensive solutions (MDE, MDO, MDCA full coverage)
```

### 4.2 Service-to-Service Connectors

**Popular Connectors (SC-200 Exam Focus):**

**1. Microsoft Entra ID (Azure AD)**

```
Connector: Azure Active Directory

Data Collected:
├─ Sign-in logs: All authentication events
│  ├─ Successful sign-ins
│  ├─ Failed sign-ins (brute force detection)
│  ├─ MFA challenges
│  ├─ Conditional Access decisions
│  └─ Risk detections (Identity Protection)
│
├─ Audit logs: Directory changes
│  ├─ User management (create, delete, modify)
│  ├─ Group changes
│  ├─ Role assignments (admin added)
│  ├─ Application registrations
│  └─ Policy changes (Conditional Access)
│
├─ Identity Protection: Risk detections
│  ├─ Impossible travel
│  ├─ Anonymous IP
│  ├─ Leaked credentials
│  ├─ Malware-linked IP
│  └─ Suspicious activity patterns
│
└─ Azure AD Identity Protection (separate connector)
   └─ Risk events and scores

Configuration:
1. Sentinel → Data connectors → Azure Active Directory
2. Prerequisites: Global Admin or Security Admin role
3. Select log types:
   - ☑ Sign-in logs
   - ☑ Audit logs
   - ☑ Risk detections (if using Identity Protection)
4. Connect: Automatic via diagnostic settings
5. Latency: 1-5 minutes (near real-time)

Tables Created:
├─ SigninLogs: Sign-in events
├─ AuditLogs: Audit events
└─ SecurityAlert (for Identity Protection)

Common Analytics Rules:
├─ Detect brute force (>10 failed logins)
├─ Detect sign-in from unfamiliar location
├─ Detect privileged role assignment (new Global Admin)
├─ Detect disabled MFA on admin accounts
└─ Detect risky sign-ins (high risk score)
```

**2. Azure Activity**

```
Connector: Azure Activity

Data Collected:
├─ Subscription-level operations:
│  ├─ Resource creation/deletion (VMs, storage, NSGs)
│  ├─ RBAC changes (role assignments)
│  ├─ Policy changes (Azure Policy)
│  ├─ Resource configuration changes
│  └─ Service health events
│
└─ Control plane operations: (Azure Resource Manager)
   ├─ Who did what?
   ├─ When?
   ├─ Where? (IP address)
   └─ Result (success/failure)

Configuration:
1. Sentinel → Data connectors → Azure Activity
2. Launch wizard → Select subscriptions
3. Connect: Automatic via diagnostic settings (all subscriptions)
4. Latency: 1-5 minutes

Table Created:
└─ AzureActivity: All subscription-level activities

Common Analytics Rules:
├─ Detect creation of VMs in unusual regions
├─ Detect mass resource deletion (sabotage)
├─ Detect privileged operations after hours
├─ Detect changes to NSG rules (open ports)
└─ Detect disabling of security features (Azure Defender)

Use Cases:
✅ Cloud security monitoring (unauthorized resource changes)
✅ Compliance auditing (who changed what?)
✅ Insider threat detection (malicious admin actions)
✅ Cost management (track resource creation)
```

**3. Microsoft Defender XDR**

```
Connector: Microsoft 365 Defender (Defender XDR)

Data Collected:
├─ Incidents: Unified incidents from MDE, MDI, MDO, MDCA
├─ Alerts: All Defender alerts
├─ Advanced Hunting: Raw telemetry tables
│  ├─ DeviceEvents (MDE): Process, network, file events
│  ├─ EmailEvents (MDO): Email telemetry
│  ├─ CloudAppEvents (MDCA): Cloud app activities
│  ├─ IdentityLogonEvents (MDI): Domain controller sign-ins
│  └─ 30+ tables (full coverage)
│
└─ 🆕 Bidirectional sync (2025): Sentinel ↔ Defender XDR

Configuration:
1. Sentinel → Data connectors → Microsoft 365 Defender
2. Prerequisites:
   - Microsoft 365 E5 or standalone Defender licenses
   - Global Admin or Security Admin role
3. Select data types:
   - ☑ Incidents & alerts (recommended)
   - ☑ Advanced Hunting (raw data) - optional, high volume
4. Connect: Automatic

Tables Created:
├─ SecurityIncident: Incidents from Defender XDR
├─ SecurityAlert: Alerts from all Defender products
└─ DeviceEvents, EmailEvents, CloudAppEvents, etc. (if Advanced Hunting enabled)

🆕 Bidirectional Sync (2025):
- Incidents created in Sentinel → appear in Defender XDR
- Incidents updated in Defender → synced to Sentinel
- Unified experience: Work in either portal

Benefits:
✅ Unified view: All Microsoft security alerts in Sentinel
✅ Correlation: Combine Defender alerts with other data sources
✅ Advanced analytics: Create custom rules on Defender data
✅ SOAR: Automate response across all Defender products
```

**4. Office 365**

```
Connector: Office 365

Data Collected:
├─ Exchange Online: Email activities
│  ├─ Emails sent/received
│  ├─ Mailbox access
│  ├─ Inbox rules created
│  ├─ Permissions changed
│  └─ Email forwarding rules
│
├─ SharePoint Online: File activities
│  ├─ File accessed/downloaded/uploaded
│  ├─ File shared (internal/external)
│  ├─ Permissions modified
│  └─ Site settings changed
│
├─ OneDrive for Business: File activities (same as SharePoint)
│
├─ Microsoft Teams: Collaboration activities
│  ├─ Team created/deleted
│  ├─ Member added/removed
│  ├─ Channel created
│  └─ Settings changed
│
└─ Azure AD (if not using separate connector)

Configuration:
1. Sentinel → Data connectors → Office 365
2. Prerequisites: Global Admin or Exchange Admin role
3. Select services:
   - ☑ Exchange
   - ☑ SharePoint
   - ☑ Teams
4. Connect: Automatic via Office 365 Management Activity API

Table Created:
└─ OfficeActivity: All Office 365 activities

Common Analytics Rules:
├─ Detect mass file deletion (ransomware)
├─ Detect suspicious inbox rules (email forwarding to external)
├─ Detect mass file download (data exfiltration)
├─ Detect external sharing of sensitive files
└─ Detect Teams external access changes

Use Cases:
✅ Data loss prevention (file exfiltration)
✅ Insider threat detection (suspicious file access)
✅ Compliance (audit file access, email usage)
✅ Ransomware detection (mass file modifications)
```

**5. Azure Firewall**

```
Connector: Azure Firewall

Data Collected:
├─ Firewall logs: Allow/deny traffic
│  ├─ Application rules: L7 filtering (URLs, FQDNs)
│  ├─ Network rules: L4 filtering (IP, port)
│  ├─ NAT rules: Destination NAT
│  └─ Threat intelligence: Blocked IPs/domains (IoCs)
│
└─ Metrics: Throughput, connections, latency

Configuration:
1. Enable diagnostic settings on Azure Firewall
2. Send logs to Log Analytics workspace (Sentinel workspace)
3. Select log categories:
   - AzureFirewallApplicationRule
   - AzureFirewallNetworkRule
   - AzureFirewallThreatIntelLog
4. Latency: 1-5 minutes

Tables Created:
├─ AzureDiagnostics (firewall logs)
└─ AzureMetrics (performance metrics)

Common Analytics Rules:
├─ Detect connections to known malicious IPs
├─ Detect unusual outbound traffic (data exfiltration)
├─ Detect C2 communication (command and control)
├─ Detect high volume traffic (DDoS, scanning)
└─ Detect blocked traffic patterns (reconnaissance)
```

**🎯 Exam Tip:**
- **Service-to-Service connectors** = No agent required (Azure native, API-based)
- **Top 5 for SC-200**: Entra ID (sign-ins, audit), Azure Activity (subscription ops), Defender XDR (incidents, alerts), Office 365 (email, files, Teams), Azure Firewall (network traffic)
- **Configuration**: Enable via diagnostic settings or connector page
- **Latency**: Near real-time (1-5 minutes)
- 🆕 **Defender XDR bidirectional sync** (2025): Incidents synced both ways
- **Tables**: SigninLogs, AuditLogs, AzureActivity, SecurityIncident, OfficeActivity, AzureDiagnostics

---

*[Continue to Part 2 for Data Collection Rules, Custom Logs, Threat Intelligence, and more...]*

---

**🎉 END OF MODULE 5 PART 1! 🎉**

You've completed **Sections 1-4** covering:
- ✅ Sentinel Overview (SIEM + SOAR, architecture, licensing)
- ✅ 🆕 2025 Updates (MDTI free, Data Lake, Defender portal migration)
- ✅ Architecture and Components (workspace, connectors, analytics, playbooks)
- ✅ Workspace Configuration (creation, retention, RBAC, multi-workspace)
- ✅ Data Connectors (service-to-service: Entra ID, Azure Activity, Defender XDR, Office 365, Firewall)

**Coming in Part 2:**
- Sections 5-8: DCR, Custom Logs, Threat Intelligence, Cost Optimization
- Part 3: Analytics Rules, NRT, Fusion, ASIM
- Part 4: Incidents, Automation, Playbooks
- Part 5: Threat Hunting, Workbooks, Advanced Topics
- Part 6: Practice Questions (20+ comprehensive scenarios)

**Progress: Module 5 Part 1 of 6 complete! Continue?** 🚀
