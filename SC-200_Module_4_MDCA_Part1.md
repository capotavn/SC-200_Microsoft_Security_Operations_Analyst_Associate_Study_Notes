# SC-200 Study Notes - Module 4: Microsoft Defender for Cloud Apps (MDCA)
## ☁️ Complete Cloud Application Security Guide - Updated for SC-200 Exam (April 21, 2025)

**Exam Weight:** This content supports ~10-15% of the SC-200 exam
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide (April 21, 2025) + Latest MDCA Updates (Sept-Oct 2025)

---

## 🎯 SC-200 Exam Objectives Covered in This Module

### **From "Manage incident response" (25-30%)**
- ✅ Investigate and remediate security risks identified by Microsoft Defender for Cloud Apps
- ✅ Investigate risky users and activities
- ✅ Manage OAuth app governance

### **From "Configure protections and detections" (15-20%)**
- ✅ Configure policies for Microsoft Defender for Cloud Apps
- ✅ Configure Cloud Discovery
- ✅ Configure Conditional Access App Control

### **From "Configure security operations infrastructure" (10-15%)**
- ✅ Connect data sources to Microsoft Defender XDR
- ✅ Configure cloud app connectors

### **Cross-Module Integration:**
- ✅ Unified incidents with MDE, MDI, MDO
- ✅ Advanced hunting (CloudAppEvents table)
- ✅ Identity protection integration

---

## 📚 Table of Contents

1. [MDCA Overview and Architecture](#1-mdca-overview-and-architecture)
2. [Cloud Discovery](#2-cloud-discovery)
3. [App Connectors and API Integration](#3-app-connectors-and-api-integration)
4. [Conditional Access App Control](#4-conditional-access-app-control)
5. [Information Protection](#5-information-protection)
6. [Threat Detection Policies](#6-threat-detection-policies)
7. [OAuth App Governance](#7-oauth-app-governance)
8. [Cloud App Security Policies](#8-cloud-app-security-policies)
9. [Activity Policies and Alerts](#9-activity-policies-and-alerts)
10. [File Policies and DLP](#10-file-policies-and-dlp)
11. [Investigation and Response](#11-investigation-and-response)
12. [Advanced Hunting for Cloud Apps](#12-advanced-hunting-for-cloud-apps)
13. [Integration with Microsoft Defender XDR](#13-integration-with-microsoft-defender-xdr)
14. [Configuration Best Practices](#14-configuration-best-practices)
15. [Exam Tips and Practice Questions](#15-exam-tips-and-practice-questions)

---

## 1. MDCA Overview and Architecture

### 1.1 What is Microsoft Defender for Cloud Apps?

**Microsoft Defender for Cloud Apps (MDCA)**, formerly Microsoft Cloud App Security (MCAS), is a **Cloud Access Security Broker (CASB)** that provides:

- **Visibility** into cloud app usage (Shadow IT discovery)
- **Data protection** across cloud applications
- **Threat protection** against cloud-based threats
- **Compliance** enforcement in SaaS applications

**🆕 Name Note:** In 2023, "Microsoft Cloud App Security" was renamed to "Microsoft Defender for Cloud Apps" to align with the Defender family branding.

### 1.2 CASB Framework

**What is a CASB (Cloud Access Security Broker)?**

A CASB sits between users and cloud applications, acting as a gatekeeper to enforce security policies.

```
The Four Pillars of CASB:

1️⃣ Visibility (Discover)
   ├─ Discover all cloud apps being used (Shadow IT)
   ├─ Identify unsanctioned apps
   ├─ Assess app risk scores
   └─ Track cloud app usage patterns

2️⃣ Data Security (Protect)
   ├─ Apply information protection labels
   ├─ Prevent data exfiltration
   ├─ Encrypt sensitive files
   └─ Control file sharing

3️⃣ Threat Protection (Defend)
   ├─ Detect anomalous behavior
   ├─ Identify compromised accounts
   ├─ Block malicious activities
   └─ Respond to threats automatically

4️⃣ Compliance (Govern)
   ├─ Enforce DLP policies
   ├─ Meet regulatory requirements
   ├─ Audit cloud app activities
   └─ Generate compliance reports
```

### 1.3 MDCA Architecture

**Deployment Modes:**

```
Microsoft Defender for Cloud Apps
│
├─ 1️⃣ Cloud Discovery (Log Collection)
│   ├─ Discovers apps via network logs
│   ├─ No user impact (passive monitoring)
│   └─ Shadow IT visibility
│
├─ 2️⃣ API Connectors (App-to-App)
│   ├─ Deep integration with sanctioned apps
│   ├─ Real-time activity monitoring
│   ├─ File-level control
│   └─ Requires app admin consent
│
├─ 3️⃣ Conditional Access App Control (Proxy)
│   ├─ Real-time session control
│   ├─ User authentication via Azure AD
│   ├─ Inline monitoring and blocking
│   └─ Works with any browser-based app
│
└─ 4️⃣ Microsoft Information Protection (MIP) Integration
    ├─ Apply sensitivity labels
    ├─ Protect files in cloud apps
    └─ Encrypt and restrict access
```

### 1.4 Data Flow Architecture

**How MDCA Works:**

```
Scenario 1: Cloud Discovery (Shadow IT)

User Device → Cloud App (Dropbox, Salesforce, etc.)
│
Log Upload (Firewall/Proxy logs)
│
↓
Microsoft Defender for Cloud Apps
├─ Parses logs
├─ Identifies apps
├─ Calculates risk scores
└─ Generates Cloud Discovery reports

Admin:
- Views discovered apps
- Sanctions/unsanctions apps
- Creates policies

───────────────────────────────────────────

Scenario 2: API Connector (Deep Integration)

User → Microsoft 365 (sanctioned app with API connector)
│
API Connection
│
↓
Microsoft Defender for Cloud Apps
├─ Monitors activities in real-time
├─ Scans files for sensitive data
├─ Applies DLP policies
└─ Generates alerts

Admin:
- Receives alerts
- Investigates activities
- Takes remediation actions

───────────────────────────────────────────

Scenario 3: Conditional Access App Control (Real-Time Control)

User → Azure AD (authentication)
│
Conditional Access Policy:
"If user = high risk, require session control"
│
↓
MDCA Proxy (Session Control)
├─ User session routed through MDCA
├─ Real-time monitoring (download, upload, copy/paste)
├─ Policy enforcement (block download of sensitive files)
└─ Logs all activities

User continues to work, but:
- Sensitive file download: BLOCKED
- Copy/paste from app: BLOCKED (if policy configured)
- All actions logged for audit

Admin:
- Views session logs
- Investigates risky sessions
- Adjusts policies
```

### 1.5 Core Capabilities

**MDCA Feature Matrix:**

| Feature | Description | Use Case | Exam Importance |
|---------|-------------|----------|-----------------|
| **Cloud Discovery** | Discover unsanctioned apps (Shadow IT) | Visibility into cloud usage | ⭐⭐⭐⭐⭐ |
| **App Connectors** | Deep integration with sanctioned apps | Monitor & protect Office 365, Google Workspace, etc. | ⭐⭐⭐⭐⭐ |
| **Conditional Access App Control** | Real-time session monitoring and control | Block sensitive file downloads, prevent copy/paste | ⭐⭐⭐⭐⭐ |
| **Information Protection** | Apply sensitivity labels, encrypt files | Protect sensitive data in cloud apps | ⭐⭐⭐⭐ |
| **Threat Detection** | Detect anomalies, compromised accounts | Identify impossible travel, mass download, etc. | ⭐⭐⭐⭐⭐ |
| **OAuth App Governance** | Monitor third-party OAuth apps | Detect overprivileged or malicious apps | ⭐⭐⭐⭐⭐ |
| **Activity Policies** | Alert on specific user activities | Detect suspicious behavior | ⭐⭐⭐⭐ |
| **File Policies** | Control file sharing and DLP | Prevent data leaks | ⭐⭐⭐⭐ |
| **Anomaly Detection** | ML-based threat detection | Detect unusual patterns | ⭐⭐⭐⭐ |
| **Cloud App Catalog** | 30,000+ app risk assessments | Evaluate app security posture | ⭐⭐⭐ |

### 1.6 Licensing

**Microsoft Defender for Cloud Apps Licensing:**

```
MDCA is included in:
✅ Microsoft 365 E5
✅ Microsoft 365 E5 Security
✅ Microsoft 365 E5 Compliance
✅ Enterprise Mobility + Security (EMS) E5

Standalone:
⚠️ Available as standalone license (~$6/user/month)

Feature Availability by License:
┌─────────────────────────────────────────────┐
│ Feature          | E5 | E3 | E3+Standalone │
├─────────────────────────────────────────────┤
│ Cloud Discovery  | ✅ | ✅ | ✅             │
│ App Connectors   | ✅ | ❌ | ✅             │
│ Session Control  | ✅ | ❌ | ✅             │
│ Threat Detection | ✅ | ❌ | ✅             │
│ OAuth Governance | ✅ | ❌ | ✅             │
└─────────────────────────────────────────────┘

Note: Basic Cloud Discovery available in Azure AD Premium P1/P2
      (limited to top discovered apps, no full dashboard)
```

### 1.7 Integration Points

**MDCA integrates with:**

```
Microsoft Security Ecosystem:
├─ Azure AD (Conditional Access, Identity Protection)
├─ Microsoft Defender XDR (Unified incidents, Advanced Hunting)
├─ Microsoft Purview (Information Protection, DLP, eDiscovery)
├─ Microsoft Defender for Endpoint (Device signals)
└─ Microsoft Defender for Identity (User behavior)

Third-Party Integrations:
├─ SIEM: Splunk, ArcSight, Generic CEF/Syslog
├─ IdP: Okta, Ping Identity
├─ DLP: Symantec, Forcepoint
└─ Ticketing: ServiceNow, Jira

Cloud Platforms:
├─ Microsoft 365 (Exchange, SharePoint, OneDrive, Teams)
├─ Google Workspace (Gmail, Drive, Calendar)
├─ Salesforce
├─ Box
├─ Dropbox
├─ AWS (via Conditional Access App Control)
├─ ServiceNow
└─ 30,000+ apps in catalog
```

### 1.8 Deployment Scenarios

**Common Use Cases:**

**Scenario 1: Shadow IT Discovery**
```
Problem: Employees using unauthorized cloud apps (Dropbox, WeTransfer)
Solution: Cloud Discovery
- Deploy log collector or upload firewall logs
- Identify all cloud apps in use
- Assess risk scores
- Sanction/unsanction apps
- Block high-risk apps via firewall
```

**Scenario 2: Protect Sensitive Data in Office 365**
```
Problem: Users sharing sensitive files externally
Solution: App Connector + File Policies
- Connect Office 365 via API connector
- Create file policy: Detect files with credit card numbers
- Action: Quarantine file, notify user, apply encryption
- Result: Sensitive data protected
```

**Scenario 3: Prevent Data Exfiltration**
```
Problem: External contractor accessing sensitive data, risk of download
Solution: Conditional Access App Control
- Configure Conditional Access policy for external users
- Enforce session control in MDCA
- Block download of files with "Confidential" label
- Allow read-only access
- Result: Data viewed but not exfiltrated
```

**Scenario 4: Detect Compromised Account**
```
Problem: Account accessed from suspicious location
Solution: Anomaly Detection
- MDCA detects impossible travel (login from US, then China 1 hour later)
- Alert generated
- Automated response: Require MFA, suspend user
- Result: Account compromise contained
```

**🎯 Exam Tip:**
- MDCA = CASB (Cloud Access Security Broker)
- **4 Pillars**: Discover (Cloud Discovery), Protect (Data Security), Defend (Threat Protection), Govern (Compliance)
- **3 Deployment Modes**: Cloud Discovery (logs), API Connectors (deep integration), Conditional Access App Control (proxy/session control)
- Licensing: Included in **Microsoft 365 E5** and **EMS E5**
- Integrates with: Azure AD, Defender XDR, Purview, MDE, MDI

---

## 2. Cloud Discovery

### 2.1 Overview

**What is Cloud Discovery?**

Cloud Discovery provides **visibility into Shadow IT** by analyzing network traffic logs to identify all cloud applications being used in your organization.

**Why It Matters:**

```
Shadow IT Risks:
❌ Unsanctioned apps (no IT oversight)
❌ Data leakage (sensitive data in unapproved apps)
❌ Compliance violations (GDPR, HIPAA, etc.)
❌ Security gaps (unvetted apps, no MFA)
❌ License waste (duplicate apps, unused subscriptions)

Cloud Discovery Benefits:
✅ Visibility: See all apps being used
✅ Risk assessment: Score apps based on 90+ criteria
✅ Usage analytics: Track bandwidth, users, transactions
✅ Sanctioning: Approve/block apps
✅ Reporting: Executive-level insights
```

### 2.2 Cloud Discovery Architecture

**How It Works:**

```
Step 1: Log Collection
───────────────────────
Firewall/Proxy → Logs (Web traffic) → Upload to MDCA

Methods:
A. Automatic upload (Defender for Endpoint integration)
B. Log collector (Docker container on-premises)
C. Manual upload (CSV/Syslog files)
D. API integration (Zscaler, iboss, Corrata)

Step 2: Log Parsing
───────────────────────
MDCA parses logs:
- Source IP
- Destination URL
- Bytes uploaded/downloaded
- User (if available)
- Timestamp

Step 3: App Identification
───────────────────────
MDCA matches URLs to 30,000+ app catalog:
- www.dropbox.com → Dropbox
- login.salesforce.com → Salesforce
- app.slack.com → Slack

Step 4: Risk Assessment
───────────────────────
Each app scored on 90+ risk factors:
- Security: Encryption, MFA, audit logs
- Compliance: GDPR, HIPAA, SOC 2
- Legal: Data ownership, SLA, privacy policy
- General: Company reputation, headquarters location

Risk Score: 0 (highest risk) to 10 (lowest risk)

Step 5: Reporting
───────────────────────
Cloud Discovery dashboard shows:
- Discovered apps
- Top apps by usage (users, traffic, transactions)
- Risk distribution
- Trends over time
```

### 2.3 Log Collection Methods

**Method 1: Defender for Endpoint Integration (Recommended)**

```
Automatic Discovery with MDE:

Prerequisites:
- Microsoft Defender for Endpoint deployed
- Windows 10/11 devices with MDE agent
- MDCA license

Configuration:
1. Defender XDR Portal → Settings → Cloud Apps
2. Microsoft Defender for Endpoint → Turn ON
3. Automatic log upload starts

Benefits:
✅ No infrastructure needed (no log collector)
✅ Automatic, continuous upload
✅ Per-device visibility
✅ Easy deployment

Limitations:
⚠️ Only for devices with MDE agent
⚠️ Limited to Windows 10/11 devices
⚠️ No visibility into non-Windows traffic
```

**Method 2: Log Collector (Docker Container)**

```
On-Premises Log Collector:

Use Case:
- Collect logs from firewalls/proxies
- Support for: Palo Alto, Cisco, Fortinet, Zscaler, etc.

Deployment:
1. Deploy Docker container on Linux VM
2. Configure firewall/proxy to send logs to collector
3. Collector uploads logs to MDCA

Configuration Steps:
1. MDCA Portal → Settings → Log collectors
2. Create data source:
   - Name: "Headquarters Firewall"
   - Source: Palo Alto Networks
   - Protocol: Syslog/FTP
3. Download Docker image deployment script
4. Run script on Linux VM:
   sudo docker run --name mycollector \
     -p 514:514/udp -p 21:21 -p 20000-20099:20000-20099 \
     -e CONSOLE=<workspace_id> -e COLLECTOR_TOKEN=<token> \
     mcr.microsoft.com/mcas/logcollector

5. Configure firewall to send logs:
   - Destination: <collector_IP>:514 (Syslog)
   - OR: FTP to <collector_IP>

Benefits:
✅ Supports multiple firewall vendors
✅ Automatic continuous upload
✅ Network-wide visibility

Limitations:
⚠️ Requires infrastructure (VM)
⚠️ Maintenance overhead (keep Docker image updated)
```

**Method 3: Manual Log Upload**

```
Manual Upload via Portal:

Use Case:
- One-time analysis
- Testing Cloud Discovery
- Small environments

Steps:
1. Export logs from firewall/proxy (CSV format)
2. MDCA Portal → Cloud Discovery → Create snapshot report
3. Upload log file
4. Wait for processing (minutes to hours depending on size)
5. View report

Benefits:
✅ No infrastructure needed
✅ Quick setup for testing

Limitations:
⚠️ Manual process (not continuous)
⚠️ Point-in-time snapshot only
⚠️ Time-consuming for regular use
```

**Method 4: API Integration**

```
Cloud Proxy Integration:

Supported Proxies:
- Zscaler
- iboss
- Corrata

Configuration:
1. MDCA Portal → Settings → Cloud Discovery
2. Automatic log upload → Configure API integration
3. Enter proxy credentials
4. Automatic upload begins

Benefits:
✅ No log collector needed
✅ Real-time data
✅ Cloud-native integration

Limitations:
⚠️ Requires compatible proxy service
⚠️ Limited to supported vendors
```

### 2.4 Cloud Discovery Dashboard

**Dashboard Overview:**

```
Cloud Discovery Dashboard (security.microsoft.com → Cloud Apps → Cloud Discovery)

Top Sections:

1. Overview
   ├─ Total discovered apps: 1,234
   ├─ Active users: 5,678
   ├─ Total traffic: 2.3 TB
   └─ Cloud risk score: 6.5/10 (moderate risk)

2. Top Apps by Category
   ├─ Collaboration & Online Meeting: Zoom, Teams, Slack
   ├─ Cloud Storage: Dropbox, Box, Google Drive
   ├─ Sales & CRM: Salesforce, HubSpot
   ├─ Development Tools: GitHub, GitLab
   └─ Social Networks: LinkedIn, Twitter

3. Risk Distribution
   ├─ High risk (0-3): 120 apps (10%)
   ├─ Medium risk (4-6): 500 apps (40%)
   ├─ Low risk (7-10): 614 apps (50%)

4. Discovered Apps Table
   ┌────────────────────────────────────────────┐
   │ App Name  | Risk | Users | Traffic | Trans│
   ├────────────────────────────────────────────┤
   │ Dropbox   | 8/10 | 450   | 1.2 TB  | 45K  │
   │ Salesforce| 9/10 | 320   | 800 GB  | 120K │
   │ WeTransfer| 4/10 | 80    | 500 GB  | 2K   │ ← High risk!
   │ GitHub    | 7/10 | 150   | 200 GB  | 80K  │
   └────────────────────────────────────────────┘

5. Trends
   - Cloud usage increasing 15% month-over-month
   - New apps discovered: 25 this month
   - High-risk app usage: Declining (good!)
```

### 2.5 App Risk Scoring

**90+ Risk Factors:**

```
Cloud App Catalog evaluates apps on:

🔒 Security (30 factors):
├─ Data encryption at rest
├─ Data encryption in transit (TLS 1.2+)
├─ Multi-factor authentication support
├─ Password policy enforcement
├─ Admin audit trail
├─ User audit trail
├─ IP address restriction
├─ Security certifications (ISO 27001, SOC 2)
└─ Penetration testing frequency

📋 Compliance (25 factors):
├─ GDPR compliance
├─ HIPAA compliance
├─ SOC 1/2/3
├─ ISO 27001
├─ PCI-DSS
├─ FedRAMP
├─ Privacy Shield
└─ Data residency options

⚖️ Legal (15 factors):
├─ Data ownership
├─ DMCA notice (copyright)
├─ Terms of service clarity
├─ Privacy policy
├─ Data retention policy
├─ Right to be forgotten
└─ User notification for data requests

🏢 General (20 factors):
├─ Company age
├─ Headquarters location
├─ Publicly traded
├─ Transparency reports
├─ Industry reputation
├─ Financial viability
└─ App popularity (users worldwide)

Risk Score Calculation:
- 0-3: High risk (red)
- 4-6: Medium risk (yellow)
- 7-10: Low risk (green)

Example:
App: WeTransfer
Risk Score: 4/10 (Medium-High Risk)
Issues:
❌ No MFA support
❌ No admin audit trail
❌ Limited data residency options
❌ Free file sharing (uncontrolled)
✅ Encrypted in transit
✅ GDPR compliant
```

### 2.6 Sanctioning and Unsanctioning Apps

**App Governance:**

**Sanctioned Apps:**
```
What: Apps approved for company use
Effect: Shows as "approved" in Cloud Discovery
Action: Users encouraged to use these apps

How to Sanction:
1. Cloud Discovery → Discovered apps
2. Select app (e.g., Microsoft 365)
3. Click "Sanction"
4. Result: App tagged as sanctioned

Benefits:
✅ Promotes secure app usage
✅ Users see "approved" badge
✅ Can integrate with Conditional Access
```

**Unsanctioned Apps:**
```
What: Apps not approved for company use
Effect: Shows as "not approved" in Cloud Discovery
Action: Users discouraged, may be blocked

How to Unsanction:
1. Cloud Discovery → Discovered apps
2. Select app (e.g., WeTransfer - high risk)
3. Click "Unsanction"
4. Optionally: Generate block script for firewall
5. Result: App tagged as unsanctioned

Blocking Unsanctioned Apps:
1. After unsanctioning, click "Generate block script"
2. Select firewall vendor (Palo Alto, Cisco, etc.)
3. Download script
4. Apply to firewall
5. Result: App traffic blocked at network level

Example Block Script (Palo Alto):
```
set address WeTransfer-URLs type fqdn fqdn wetransfer.com
set address WeTransfer-URLs type fqdn fqdn we.tl
set security-rule "Block-Unsanctioned-Apps" destination WeTransfer-URLs action deny
```
```

### 2.7 Cloud Discovery Reports

**🆕 November 2024: Executive Summary Report Update**

**Old Report (Pre-Nov 2024):**
- 26 pages (too long!)
- Lots of technical details
- Not executive-friendly

**🆕 New Report (Nov 2024+):**
- **6 pages** (streamlined!)
- Focus on actionable insights
- Executive-friendly format

**Report Sections:**

```
Page 1: Executive Summary
- Key metrics: Apps, users, traffic
- Top risks identified
- Recommendations

Page 2: Cloud Usage Overview
- Cloud adoption trend
- Top app categories
- Sanctioned vs unsanctioned usage

Page 3: Risk Assessment
- High-risk apps
- Security gaps
- Compliance concerns

Page 4: Shadow IT Analysis
- Unsanctioned app usage
- Duplicate app subscriptions
- Cost savings opportunities

Page 5: Top Apps Deep Dive
- Detailed analysis of top 10 apps
- Risk scores and issues
- Recommendations

Page 6: Action Plan
- Prioritized recommendations
- Quick wins
- Long-term strategy
```

**Generating Report:**

```
1. Cloud Discovery → Reports → Create executive report
2. Select time period (last 30/60/90 days)
3. Generate
4. Download PDF
5. Share with leadership
```

### 2.8 Continuous Discovery vs Snapshot Reports

**Comparison:**

| Feature | Continuous Discovery | Snapshot Reports |
|---------|---------------------|------------------|
| **Setup** | Log collector or MDE integration | Manual log upload |
| **Frequency** | Continuous (real-time) | One-time (on-demand) |
| **Use Case** | Ongoing monitoring | Initial assessment, testing |
| **Dashboard** | Live dashboard | Static report |
| **Trends** | Historical trends visible | Point-in-time only |
| **Alerting** | Policies can trigger alerts | No alerting |
| **Effort** | Initial setup, then automated | Manual upload each time |

**Recommendation:** Use **Continuous Discovery** for production environments, **Snapshot Reports** for initial assessment or demos.

### 2.9 Cloud Discovery Policies

**Anomaly Detection Policies:**

```
Example: New Discovered High-Risk App

Policy:
- Trigger: New app discovered with risk score < 5
- Alert: Email to security team
- Action: Auto-unsanction app

Configuration:
1. Cloud Discovery → Anomaly detection policy → Create policy
2. Policy name: "Alert on high-risk apps"
3. Filters:
   - App risk score: Less than 5
   - First seen: Last 7 days
4. Alert: Send email to: security@contoso.com
5. Governance: Unsanction app automatically
6. Save

Result: Any new high-risk app triggers alert and is auto-unsanctioned
```

**🎯 Exam Tip:**
- **Cloud Discovery** = Visibility into **Shadow IT** (unsanctioned apps)
- **3 Log Collection Methods**: MDE integration (automatic), Log collector (Docker), Manual upload
- **30,000+ apps** in Cloud App Catalog, scored on **90+ risk factors**
- **Risk Score**: 0-3 (high), 4-6 (medium), 7-10 (low)
- **Sanctioned** = Approved, **Unsanctioned** = Not approved (can block)
- 🆕 **Executive Report**: Reduced from **26 pages to 6 pages** (Nov 2024)
- **Continuous Discovery** = Recommended for production

---

## 3. App Connectors and API Integration

### 3.1 Overview

**What are App Connectors?**

App Connectors provide **deep, API-based integration** with cloud applications, enabling:
- Real-time activity monitoring
- File-level visibility and control
- User behavior analytics
- Automated governance actions

**App Connectors vs Cloud Discovery:**

| Feature | Cloud Discovery | App Connectors |
|---------|----------------|----------------|
| **Deployment** | Log analysis (passive) | API integration (active) |
| **Visibility** | Network traffic only | Activities, files, users, settings |
| **Control** | Read-only (visibility) | Read/write (control) |
| **Depth** | Shallow (app names, URLs) | Deep (file names, permissions, sharing) |
| **Action** | Alert only | Alert + remediate |
| **Apps** | 30,000+ (any app) | ~100 supported apps |

**When to Use:**
- **Cloud Discovery**: Discover all apps (Shadow IT)
- **App Connectors**: Deep protection for sanctioned apps (O365, Google Workspace, Salesforce, etc.)

### 3.2 Supported Apps

**Major App Connectors:**

```
Microsoft:
✅ Microsoft 365 (Exchange, SharePoint, OneDrive, Teams)
✅ Azure (Azure AD, Azure Resource Manager)

Google:
✅ Google Workspace (Gmail, Drive, Calendar, Admin)

Collaboration:
✅ Box
✅ Dropbox
✅ Slack
✅ Zoom

CRM & Business:
✅ Salesforce
✅ ServiceNow
✅ Workday

Dev Tools:
✅ GitHub
✅ Atlassian (Jira, Confluence)

Other:
✅ AWS
✅ Okta
✅ Zendesk
✅ DocuSign

Full list: ~100 apps
Check: https://learn.microsoft.com/en-us/defender-cloud-apps/enable-instant-visibility-protection-and-governance-actions-for-your-apps
```

### 3.3 Connecting Apps

**Connection Process:**

**Example: Connecting Microsoft 365**

```
Prerequisites:
- Global admin or App admin role in MDCA
- Global admin consent in Azure AD

Steps:
1. MDCA Portal → Settings → App connectors
2. Click "+ Connect an app"
3. Select: Office 365
4. Click "Connect Office 365"
5. Sign in with Global Admin account
6. Grant permissions:
   - Read Office 365 activities
   - Read Office 365 files
   - Manage Office 365 files (optional)
7. Connection established ✅

Permissions Granted:
- ActivityFeed.Read (read audit logs)
- Files.Read.All (scan files)
- Files.ReadWrite.All (quarantine files) [if enabled]
- Directory.Read.All (read users/groups)

Time to Full Sync:
- Initial: 1-2 hours
- Ongoing: Real-time

Data Available:
✅ User activities (login, file access, sharing, etc.)
✅ Files (name, owner, sharing permissions, labels)
✅ Admin activities (config changes, user management)
✅ Alerts (DLP violations, anomalies)
```

**Example: Connecting Google Workspace**

```
Prerequisites:
- Google Workspace Super Admin account
- Domain verification

Steps:
1. MDCA Portal → Settings → App connectors
2. Click "+ Connect an app"
3. Select: Google Workspace
4. Follow instructions:
   a. Enable API access in Google Admin Console
   b. Create service account
   c. Grant domain-wide delegation
   d. Download private key JSON file
5. Upload JSON file to MDCA
6. Connection established ✅

Permissions Granted:
- Admin SDK API (read audit logs)
- Drive API (scan files)
- Gmail API (monitor email)

Time to Full Sync:
- Initial: 2-4 hours
- Ongoing: Near real-time (5-15 min delay)

Data Available:
✅ User activities (login, file access, Gmail actions)
✅ Files in Google Drive
✅ Admin activities
✅ Gmail DLP events
```

### 3.4 App Connector Status

**Monitoring Connection Health:**

```
App Connectors → Status

Health Status:
✅ Connected (green): All systems operational
⚠️ Warning (yellow): Partial connectivity, some data missing
❌ Error (red): Connection failed, no data syncing

Common Issues:

1. Permission Revoked
   Symptom: Status changes from Connected to Error
   Cause: Admin revoked app permissions
   Fix: Re-consent app in Azure AD

2. API Rate Limiting
   Symptom: Warning status, delayed data
   Cause: Too many API calls (large org)
   Fix: Automatic throttling by MDCA, no action needed

3. Service Account Expired (Google)
   Symptom: Error status
   Cause: Google service account key expired (10 years default)
   Fix: Generate new key, re-upload to MDCA

4. License Changes
   Symptom: Some users missing from reports
   Cause: Users lost MDCA license
   Fix: Ensure all users have appropriate licenses
```

### 3.5 Data Visibility with App Connectors

**What Can You See?**

**Activities:**
```
Example: Microsoft 365 Connector

Activities Monitored:
├─ Exchange Online:
│  ├─ Email sent/received
│  ├─ Mailbox rules created
│  ├─ Delegate permissions added
│  └─ Inbox rule forwarding emails
│
├─ SharePoint/OneDrive:
│  ├─ File uploaded/downloaded
│  ├─ File shared (internal/external)
│  ├─ File accessed
│  ├─ File deleted
│  ├─ Permission changed
│  └─ Sharing link created
│
├─ Teams:
│  ├─ Team created
│  ├─ Member added/removed
│  ├─ Channel created
│  ├─ File shared in Teams
│  └─ Meeting created
│
└─ Azure AD:
   ├─ User sign-in
   ├─ Password reset
   ├─ MFA registered
   ├─ Conditional Access policy applied
   └─ Admin role assigned

Activity Log Example:
┌────────────────────────────────────────────────┐
│ Time      | User         | Activity    | App  │
├────────────────────────────────────────────────┤
│ 14:32:05  | john@cont... | Download    | SPO  │
│ 14:32:08  | john@cont... | Share ext.  | SPO  │ ← Suspicious!
│ 14:32:15  | john@cont... | Mass down.  | SPO  │ ← Alert!
└────────────────────────────────────────────────┘
```

**Files:**
```
Example: OneDrive File Scan

File Metadata:
- File name: Financial_Report_Q3_2025.xlsx
- Owner: cfo@contoso.com
- Size: 5 MB
- Last modified: 2025-10-20
- Sharing: External link (anyone with link)
- Label: Confidential (Microsoft Purview)
- Content inspection: Contains SSNs, credit card numbers

Policy Match:
❌ Confidential file shared externally
❌ Contains PII (SSN)
❌ No DLP encryption applied

Actions Taken:
1. Alert sent to admin
2. File quarantined (access blocked)
3. User notified
4. Incident created in Defender XDR
```

### 3.6 App Governance

**Automated Actions:**

**File Governance:**
```
Scenario: Quarantine files with sensitive data

Policy: File Policy
- Conditions: File contains credit card numbers
- App: Office 365 (SharePoint/OneDrive)
- Action: Quarantine file

Result:
1. MDCA scans all files in SharePoint/OneDrive
2. File "customer_list.xlsx" contains credit cards
3. File access blocked (user sees: "File quarantined by admin")
4. Owner receives notification:
   "Your file was quarantined due to sensitive content.
    Contact IT Security to review."
5. Admin investigates:
   - View file metadata
   - Preview content (safely)
   - Options: Restore, Delete, Apply encryption

Governance Actions Available:
- Remove external collaborators
- Remove public sharing
- Quarantine file
- Put user in admin quarantine (file read-only)
- Apply sensitivity label
- Trash file
- Remove direct shared link
```

**User Governance:**
```
Scenario: Suspend user on suspicious activity

Policy: Activity Policy
- Conditions: Mass file download (>100 files in 1 hour)
- App: Office 365
- Action: Suspend user

Result:
1. User "contractor@external.com" downloads 150 files
2. Alert triggered
3. MDCA suspends user account (Azure AD)
4. User sign-in blocked
5. Admin notified
6. SOC investigates

Governance Actions Available:
- Suspend user
- Require user to sign in again (revoke session)
- Notify user
- Notify admin
- Notify user manager
- Confirm user compromised (mark in Azure AD Identity Protection)
```

### 3.7 Limitations and Considerations

**App Connector Limitations:**

```
1. API Rate Limits
   - Apps have API call quotas
   - MDCA respects limits (may delay some data)
   - Large orgs may experience slight delays

2. Permissions Required
   - Admin consent needed (Global Admin)
   - Some orgs restrict admin consent
   - Requires planning and approvals

3. Data Residency
   - MDCA processes data in Microsoft datacenters
   - May cross geographic boundaries
   - Check compliance requirements

4. Not All Apps Supported
   - ~100 apps have native connectors
   - Others require Conditional Access App Control
   - Custom apps need App Control proxy

5. Retroactive Scanning Limited
   - Activities: 30-90 days historical (varies by app)
   - Files: Current state only (not historical versions)
   - Can't scan deleted files (unless still in recycle bin)

6. Performance Impact
   - File scanning consumes API quota
   - May slow down app for end users (rare)
   - Usually imperceptible
```

**🎯 Exam Tip:**
- **App Connectors** = **Deep API integration** with cloud apps (real-time monitoring, control)
- **~100 supported apps** (Microsoft 365, Google Workspace, Salesforce, Box, Dropbox, etc.)
- **Connection requires**: Admin consent, appropriate permissions
- **Data available**: Activities (login, file access, sharing), Files (metadata, content), Settings
- **Governance actions**: Quarantine files, Suspend users, Apply labels, Remove sharing
- **Limitations**: API rate limits, Admin consent required, Not all apps supported

---

## 4. Conditional Access App Control

### 4.1 Overview

**What is Conditional Access App Control?**

**Conditional Access App Control** provides **real-time session monitoring and control** by proxying user sessions through Microsoft Defender for Cloud Apps.

**How It Differs from App Connectors:**

| Feature | App Connectors | Conditional Access App Control |
|---------|---------------|-------------------------------|
| **Method** | API-based (post-action) | Proxy-based (real-time) |
| **Timing** | After activity occurs | During activity (inline) |
| **Control** | Retroactive (alert after) | Proactive (block before) |
| **Supported Apps** | ~100 with native connectors | Any browser-based app |
| **Session Visibility** | Activity logs only | Full session recording |
| **Granularity** | App-level | Session-level (per-action) |

**Key Capabilities:**

```
Real-Time Controls:
✅ Block download of sensitive files
✅ Block copy/paste from app
✅ Block print
✅ Watermark documents
✅ Protect files on download (auto-encrypt)
✅ Monitor all session activities
```

### 4.2 Architecture

**How Conditional Access App Control Works:**

```
Normal Access (Without App Control):

User → Azure AD (authentication) → Cloud App (direct access)

────────────────────────────────────────────────────

With Conditional Access App Control:

Step 1: User authenticates
User → Azure AD → Conditional Access Policy:
"If user = high risk OR external,
 Require session control"

Step 2: Azure AD redirects to MDCA
Azure AD → Microsoft Defender for Cloud Apps Proxy

Step 3: MDCA proxies session
MDCA Proxy ↔ Cloud App
├─ User session routed through MDCA
├─ All actions monitored in real-time:
│  - File download attempt
│  - Copy/paste action
│  - Print action
│  - Sharing action
│
├─ Policies evaluated for each action:
│  "Can this user download this file?"
│  └─ Check: File sensitivity label
│      Check: User location
│      Check: Device compliance
│
└─ Action: Allow or Block

User Experience:
- Mostly transparent (slight redirect delay ~500ms)
- If blocked: "This action is restricted by your organization"
- All actions logged for audit

Admin View:
- Activity log → Session details
- See: Every action attempted, allowed/blocked
- Forensics: Review session recording
```

### 4.3 Deployment Models

**Deployment Options:**

**1. Featured Apps (Recommended)**

```
What: Pre-integrated apps (Microsoft, Google, Salesforce, etc.)
Setup: Minimal (just create Conditional Access policy)

Featured Apps:
- Microsoft 365 (SharePoint, OneDrive, Teams)
- Google Workspace (Drive, Gmail)
- Salesforce
- Box
- Dropbox
- Slack
- Zoom
- ServiceNow
- GitHub
- ~100 apps

Configuration:
1. Azure AD → Conditional Access → Create policy
2. Users: Select users/groups
3. Cloud apps: Select app (e.g., Office 365)
4. Conditions: Device, Location, Risk (optional)
5. Session: Use Conditional Access App Control
   - Options:
     * Monitor only (no blocking)
     * Block downloads
     * Use custom session policy
6. Save

Result: Users accessing selected app will be proxied through MDCA
```

**2. Custom Apps (Any SAML-based app)**

```
What: Any app that uses SAML SSO via Azure AD
Setup: More complex (deploy app in MDCA catalog)

Use Cases:
- Custom line-of-business apps
- Unsupported SaaS apps
- On-premises apps published via Azure AD App Proxy

Configuration:
1. MDCA → Conditional Access App Control → Apps
2. "+ Add app"
3. Select: Custom app (SAML)
4. App name: "Custom HR Portal"
5. SSO URL: https://hr.contoso.com/saml
6. Entity ID: urn:hr:contoso
7. Upload SAML metadata from Azure AD
8. Test connection
9. Create Conditional Access policy (same as featured apps)
10. Apply session controls

Result: Custom app now controlled by MDCA proxy
```

### 4.4 Session Policies

**Policy Types:**

**1. Access Policy**

```
Control: WHO can access the app

Example: Block external users from accessing sensitive apps

Policy:
- Name: "Block external users from HR app"
- App: Custom HR Portal
- Users: External users (guest accounts)
- Action: Block access

Result: External users see "Access denied"
```

**2. Session Policy**

```
Control: WHAT users can do within the app

Types:
a) Monitor Only
b) Control file downloads
c) Control file uploads
d) Block activities based on real-time inspection

Example 1: Block download of Confidential files

Policy:
- Name: "Block download of confidential files"
- App: Office 365
- Activity: Download
- Conditions: File label = "Confidential"
- Action: Block

Result: User clicks Download → "This file cannot be downloaded"

Example 2: Watermark sensitive documents

Policy:
- Name: "Watermark Highly Confidential files"
- App: Office 365
- Activity: Download, Print, Copy
- Conditions: File label = "Highly Confidential"
- Action: Protect (Apply watermark)

Result: 
- User downloads file → Auto-watermarked with username/timestamp
- User prints file → Watermark appears on printout
- User copies text → Watermark appears in destination
```

**3. Anomaly Detection Policy**

```
Control: Detect suspicious session behavior

Built-in Anomaly Detections:
- Impossible travel during session
- Activity from anonymous IP
- Mass download
- Ransomware activity
- Unusual file share

Example: Detect mass download in session

Policy: (Built-in, auto-enabled)
- Trigger: User downloads >100 files in single session
- Alert: Yes
- Action: Suspend user, Notify admin

Result:
1. User downloads 150 files
2. Alert triggered mid-session
3. Session terminated
4. User account suspended
5. Admin notified for investigation
```

### 4.5 Real-Time Protection Actions

**Available Actions:**

```
1. Monitor
   - Log activity only
   - No blocking
   - For baselining, investigation

2. Block
   - Prevent action entirely
   - User sees: "This action is restricted"
   - Use: High-security scenarios

3. Protect (Apply Watermark/Encryption)
   - Allow action but apply protection
   - Watermark: Stamp file with user info
   - Encryption: Auto-encrypt on download
   - Use: Controlled data access

4. Verify (Step-up Authentication)
   - Require additional authentication
   - Use: Sensitive actions (delete, share externally)

5. Bypass
   - Exclude from policy
   - Use: Admins, IT staff (with logging)
```

**Action Matrix:**

| Activity | Monitor | Block | Protect | Verify |
|----------|---------|-------|---------|--------|
| **Download** | ✅ Log | ✅ Prevent | ✅ Watermark/Encrypt | ✅ Require MFA |
| **Upload** | ✅ Log | ✅ Prevent | ✅ Scan + Label | ✅ Require MFA |
| **Copy/Paste** | ✅ Log | ✅ Prevent | ⚠️ N/A | ⚠️ N/A |
| **Print** | ✅ Log | ✅ Prevent | ✅ Watermark | ✅ Require MFA |
| **Share** | ✅ Log | ✅ Prevent | ✅ Restrict to internal | ✅ Require MFA |

### 4.6 User Experience

**What Users See:**

**Scenario 1: Normal Access (No Restrictions)**
```
User Experience:
1. User navigates to https://sharepoint.contoso.com
2. Azure AD authentication (sign-in if not already)
3. Brief redirect (~500ms) - user may notice URL change:
   Old: sharepoint.contoso.com
   New: sharepoint.contoso.com.mcas.ms (proxied)
4. SharePoint loads normally
5. User works as usual
6. All activities monitored but not blocked

User Notice: Minimal (just URL change, works normally)
```

**Scenario 2: Blocked Download**
```
User Experience:
1. User clicks Download on "Financial_Report.xlsx" (label: Confidential)
2. MDCA evaluates policy:
   - File label: Confidential ✓
   - User: External contractor ✓
   - Policy: Block download of Confidential files
3. User sees:
   ┌──────────────────────────────────────┐
   │  🚫 Download Blocked                 │
   │                                      │
   │  This file is classified as          │
   │  Confidential and cannot be          │
   │  downloaded by external users.       │
   │                                      │
   │  Contact your administrator for help│
   └──────────────────────────────────────┘
4. Download does not occur
5. Activity logged
6. Admin notified (optional)

User Notice: Clear block message
```

**Scenario 3: Watermarked Download**
```
User Experience:
1. User clicks Download on "Strategy_Roadmap.pptx" (label: Internal Only)
2. MDCA evaluates policy:
   - File label: Internal Only ✓
   - User: Internal employee ✓
   - Policy: Protect with watermark
3. User sees:
   ┌──────────────────────────────────────┐
   │  ⓘ Protected Download                │
   │                                      │
   │  This file has been watermarked with │
   │  your identity for security tracking.│
   │                                      │
   │  [Download]                          │
   └──────────────────────────────────────┘
4. File downloads with watermark:
   - Header: "Downloaded by john@contoso.com on 2025-10-22 15:30"
   - Footer: "Confidential - Internal Use Only"
5. User can use file, but watermark visible on every page

User Notice: Notification + watermarked file
```

### 4.7 Session Activity Logs

**Monitoring Sessions:**

```
MDCA Portal → Cloud Apps → Activity log → Session control

Activity Log View:
┌────────────────────────────────────────────────────────┐
│ Time      | User        | Activity   | App    | Result│
├────────────────────────────────────────────────────────┤
│ 14:32:05  | john@ext... | Download   | SPO    | Block │ ← Blocked!
│ 14:32:08  | john@ext... | View       | SPO    | Allow │
│ 14:32:15  | jane@con... | Download   | SPO    | Allow │
│ 14:32:20  | jane@con... | Copy text  | SPO    | Block │
│ 14:32:25  | bob@cont... | Print      | SPO    | Protect (Watermark)
└────────────────────────────────────────────────────────┘

Session Details (Click to expand):
Session ID: sess-12345-67890
User: john@external.com (external contractor)
App: SharePoint Online
Duration: 45 minutes
Device: Windows 10, Edge browser
Location: United States (IP: 203.0.113.45)
Risk: Medium (external user + unusual download pattern)

Activities in Session (24 activities):
├─ 14:30:00 - Sign-in (Allow)
├─ 14:30:15 - Browse site (Allow)
├─ 14:31:00 - Open file "Report.xlsx" (Allow)
├─ 14:32:05 - Download "Report.xlsx" (Block) ← Policy triggered
├─ 14:32:08 - View file online (Allow)
├─ 14:32:15 - Search "financial data" (Allow)
├─ 14:35:00 - Access denied (tried to download again)
└─ ... (18 more activities)

Policy Matches:
⚠️ Blocked: Download of Confidential file (Policy: "Block ext. downloads")
ℹ️ Monitored: 22 other activities (no policy violations)

Admin Actions Available:
- End session (force sign-out)
- Suspend user
- Investigate further (view file details)
- Export session log (forensics)
```

### 4.8 Advanced Scenarios

**Scenario 1: External Partner Access with Restrictions**

```
Business Need:
- External contractor needs access to SharePoint
- Can VIEW files, but NOT download, copy, print

Configuration:
1. Azure AD → Conditional Access
   - Users: External users (guest accounts)
   - Apps: Office 365
   - Session: Use Conditional Access App Control

2. MDCA → Session policy → Create
   - Name: "External contractors - Read-only access"
   - App: Office 365
   - Users: External users
   - Activities: Download, Print, Copy text
   - Action: Block

Result:
- External contractor can browse SharePoint
- Can view files in browser
- Cannot download, print, or copy
- All activities logged
```

**Scenario 2: Download Protection with Auto-Encryption**

```
Business Need:
- Allow file downloads, but auto-encrypt sensitive files

Configuration:
1. Conditional Access: Enable session control for all users

2. MDCA → Session policy → Create
   - Name: "Auto-encrypt Confidential files on download"
   - App: Office 365
   - Activity: Download
   - Conditions: File label = "Confidential"
   - Action: Protect
     * Apply encryption: Yes
     * Rights: Read-only (no edit, no print)

Result:
- User downloads "Q3_Report.xlsx" (Confidential)
- File auto-encrypted on download
- User can open file (Azure Information Protection)
- File is read-only, watermarked
- Cannot be forwarded or printed
```

**🎯 Exam Tip:**
- **Conditional Access App Control** = **Real-time session control** (proxy)
- Works with **any browser-based app** (SAML SSO via Azure AD)
- **~100 featured apps** (pre-integrated: O365, Google, Salesforce, etc.)
- **Custom apps** supported (SAML-based)
- **Session controls**: Block download, Block copy/paste, Watermark, Auto-encrypt
- **Requires**: Azure AD Conditional Access policy + MDCA session policy
- **User experience**: Transparent (slight URL redirect, e.g., .mcas.ms suffix)
