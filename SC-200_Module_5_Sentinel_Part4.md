# SC-200 Study Notes - Module 5: Microsoft Sentinel (Part 4)
## 🎯 Incident Management & Automation (SOAR)

**Continuation of Parts 1-3** - Sections 16-20
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide + Latest Sentinel Updates

---

## 📚 Table of Contents - Part 4

16. [Incident Management Overview](#16-incident-management-overview)
17. [Incident Investigation](#17-incident-investigation)
18. [Investigation Graph & Timeline](#18-investigation-graph--timeline)
19. [Automation Rules](#19-automation-rules)
20. [Playbooks (Logic Apps)](#20-playbooks-logic-apps)
21. [SOAR Integration](#21-soar-integration)

---

## 16. Incident Management Overview

### 16.1 What is an Incident?

**Incident Definition:**

```
Incident = Security event requiring investigation and response

Incident vs Alert:
┌────────────────────────────────────────────────────────┐
│ Aspect        | Alert              | Incident          │
├────────────────────────────────────────────────────────┤
│ Definition    | Single detection   | Grouped alerts    │
│ Source        | Analytics rule     | Alert grouping    │
│ Volume        | High (10,000+/day) | Lower (1,000/day) │
│ Investigation | No workflow        | Full workflow     │
│ Assignment    | Not assigned       | Assigned to analyst│
│ Status        | N/A                | New/Active/Closed │
│ Context       | Limited            | Rich (entities)   │
└────────────────────────────────────────────────────────┘

Why Group Alerts into Incidents?
1. Reduce noise: 10 related alerts → 1 incident (easier to manage)
2. Context: See full attack chain (not isolated events)
3. Workflow: Assign, track, close (clear ownership)
4. Metrics: Measure MTTR (Mean Time to Resolve)
5. Reporting: Incident reports (not alert reports)

Example:
Alert 1: Suspicious sign-in from IP 203.0.113.50
Alert 2: Mass file download by same user
Alert 3: External sharing of files by same user
→ Incident: "Potential data exfiltration by user@contoso.com"
```

### 16.2 Incident Lifecycle

**From Creation to Closure:**

```
Incident Lifecycle Stages:

1️⃣ New (Alert → Incident Created)
   ├─ Trigger: Analytics rule generates alert(s)
   ├─ Grouping: Alerts grouped by entities/time (or separate incidents)
   ├─ Status: New
   ├─ Owner: Unassigned
   └─ Next: Triage (assess severity, assign)

2️⃣ Active (Under Investigation)
   ├─ Triage: Analyst reviews incident details
   ├─ Assignment: Assign to analyst or team
   ├─ Investigation: Gather evidence, analyze
   ├─ Status: Active
   ├─ Actions: Run queries, check entities, collect logs
   └─ Next: Response or escalation

3️⃣ Response (Remediation)
   ├─ Containment: Block IP, disable user, isolate device
   ├─ Eradication: Remove malware, close backdoors
   ├─ Recovery: Restore systems, reset passwords
   ├─ Status: Still Active (until resolved)
   └─ Next: Closure

4️⃣ Closed (Resolved)
   ├─ Classification:
   │  ├─ True Positive - Confirmed threat
   │  ├─ False Positive - Not a threat (tuning needed)
   │  ├─ Benign Positive - True event, not malicious
   │  └─ Undetermined - Cannot confirm (insufficient data)
   ├─ Resolution: Document findings, actions taken
   ├─ Status: Closed
   └─ Next: Post-incident review, rule tuning

Incident Lifecycle Diagram:
┌─────────┐  Triage   ┌─────────┐  Investigate  ┌─────────┐
│   New   │ ────────> │ Active  │ ───────────>  │Response │
│(Alert)  │           │(Assigned)│               │(Contain)│
└─────────┘           └─────────┘               └────┬────┘
                                                      │
                                                      ▼
                                                ┌─────────┐
                                                │ Closed  │
                                                │(Resolved)│
                                                └─────────┘

Time Metrics:
├─ MTTT (Mean Time to Triage): Alert → Analyst review (target <15 min)
├─ MTTI (Mean Time to Investigate): Assigned → Root cause (target <1 hour)
├─ MTTR (Mean Time to Respond): Alert → Remediation (target <4 hours)
└─ MTTC (Mean Time to Close): Alert → Closure (target <24 hours)
```

### 16.3 Incident Properties

**Key Incident Fields:**

```
Incident Details (Portal View):

1️⃣ Identification
   ├─ Incident ID: Unique identifier (#12345)
   ├─ Title: "Suspicious PowerShell execution on DESKTOP-123"
   ├─ Description: Auto-generated or custom
   ├─ Created time: When incident created
   └─ Number: Sequential number (for easy reference)

2️⃣ Severity
   ├─ Informational: FYI (no immediate action)
   ├─ Low: Minor issue (investigate when available)
   ├─ Medium: Potential threat (investigate within 24h)
   ├─ High: Serious threat (investigate within 4h)
   └─ Critical: Immediate threat (investigate NOW, <1h)

3️⃣ Status
   ├─ New: Just created, not yet reviewed
   ├─ Active: Under investigation
   └─ Closed: Resolved (with classification)

4️⃣ Assignment
   ├─ Owner: Assigned analyst (or unassigned)
   ├─ Owner email: For notifications
   └─ Team: Which SOC team (Tier 1, Tier 2, etc.)

5️⃣ Classification (Closed Incidents)
   ├─ True Positive: Confirmed threat
   │  └─ Sub-types: Malware, Phishing, Data Exfiltration, etc.
   ├─ False Positive: Not a threat (rule needs tuning)
   │  └─ Action: Tune rule (add exclusions, adjust threshold)
   ├─ Benign Positive: True event, not malicious
   │  └─ Example: Authorized admin using PowerShell
   └─ Undetermined: Cannot determine (insufficient evidence)

6️⃣ Detection
   ├─ Detection source: Sentinel, Defender XDR, etc.
   ├─ Analytics rule: Which rule triggered incident
   ├─ Alert count: Number of alerts grouped
   └─ First/Last alert time: Time range

7️⃣ Entities
   ├─ Accounts: Users involved
   ├─ Hosts: Devices involved
   ├─ IPs: IP addresses
   ├─ Files: Files involved
   ├─ URLs: URLs involved
   └─ More: Processes, file hashes, registry keys, etc.

8️⃣ Evidence
   ├─ Alerts: Individual alerts (detailed view)
   ├─ Events: Raw log events (linked)
   ├─ Timeline: Chronological event sequence
   └─ Investigation graph: Visual relationships

9️⃣ Comments
   ├─ Analyst notes: Investigation findings
   ├─ Collaboration: Team communication
   ├─ Actions taken: Remediation steps
   └─ Follow-up: Tasks for other analysts

🔟 Tags
   ├─ Custom labels: VIP user, Confirmed breach, etc.
   ├─ Use: Filtering, reporting, prioritization
   └─ Examples: "Executive", "Production Server", "Under Attack"
```

### 16.4 Incident Triage Process

**First Response - What to Do When Incident Fires:**

```
Triage Steps (First 5-10 Minutes):

Step 1: Quick Assessment (30 seconds)
─────────────────────────────────────────
Questions:
├─ What happened? (Read title, description)
├─ How severe? (Check severity, entities)
├─ Is this real? (Quick smell test)
└─ Who's affected? (VIP user? Production server?)

Action:
- Read incident title + description
- Check severity (Critical/High → immediate action)
- Scan entities (recognizable users/IPs/hosts?)

Step 2: Context Gathering (2-3 minutes)
─────────────────────────────────────────
Questions:
├─ What triggered this? (Which analytics rule?)
├─ How many alerts? (Single alert or multiple?)
├─ What entities? (User, IP, host details)
├─ When? (Recent or historical?)
└─ Any related incidents? (Same user/host earlier today?)

Action:
- Review alerts (individual alert details)
- Check entities (click to see entity details)
- Review timeline (event sequence)
- Search for related incidents (same entities)

Step 3: Initial Classification (1-2 minutes)
─────────────────────────────────────────
Questions:
├─ True positive? (Looks like real threat?)
├─ False positive? (Known issue, false alarm?)
├─ Benign positive? (Authorized activity?)
└─ Need more info? (Cannot determine yet)

Action:
- Quick verdict (TP/FP/BP/Undetermined)
- If FP: Close immediately, note reason, tune rule later
- If TP: Continue to Step 4
- If Undetermined: Escalate or investigate further

Step 4: Prioritization (1 minute)
─────────────────────────────────────────
Questions:
├─ How urgent? (Severity + business impact)
├─ Who's affected? (VIP? Production?)
├─ What's the risk? (Data loss? Downtime?)
└─ Other incidents? (Multiple high-priority?)

Action:
- Adjust severity (increase if VIP/production)
- Assign priority (Critical = P1, High = P2, Medium = P3)
- Add tags ("VIP", "Production", "Urgent")

Step 5: Assignment (30 seconds)
─────────────────────────────────────────
Questions:
├─ Who should handle? (Tier 1, Tier 2, specialist?)
├─ Escalate? (Beyond my expertise?)
└─ Team available? (On-call analyst?)

Action:
- Assign to analyst or team
- Change status: New → Active
- Add comment: "Assigned to John for investigation"

Step 6: Initial Response (Optional - 1-2 minutes)
─────────────────────────────────────────
If Critical/High severity:
├─ Containment: Block IP (playbook), disable user (manual)
├─ Notification: Alert CISO, security manager
└─ Documentation: Add comment with actions taken

Triage Decision Tree:
┌─────────────────────────────────────────────────────────┐
│ Is severity Critical or High?                           │
├─────────────────────────────────────────────────────────┤
│ YES → Is it VIP or Production?                          │
│   ├─ YES → Immediate action (assign P1, contain threat)│
│   └─ NO → Assign quickly (investigate within 1 hour)   │
│                                                          │
│ NO → Is it False Positive?                              │
│   ├─ YES → Close immediately (tune rule later)         │
│   └─ NO → Normal workflow (assign, investigate)        │
└─────────────────────────────────────────────────────────┘

Triage KPIs:
├─ MTTT (Mean Time to Triage): <15 minutes (target)
├─ False positive closure rate: <5 minutes (quick close)
├─ True positive escalation rate: <10 minutes (fast escalation)
└─ Triage accuracy: 90%+ correct initial classification
```

### 16.5 Incident Workspace Management

**Portal Navigation & Actions:**

```
Sentinel Incident Portal (security.microsoft.com or Azure portal):

Main View:
─────────────────────────────────────────
Sentinel → Incidents

Filters (Top Bar):
├─ Status: New, Active, Closed
├─ Severity: Critical, High, Medium, Low, Informational
├─ Owner: Unassigned, Assigned to me, Assigned to others
├─ Time range: Last 24h, 7d, 30d, custom
├─ Detection source: Sentinel, Defender XDR, Defender for Cloud
└─ Search: Incident ID, title, entity name

Columns (Customizable):
├─ Severity (icon: red/orange/yellow/blue)
├─ Incident ID (#12345)
├─ Title (clickable → incident details)
├─ Status (New, Active, Closed)
├─ Owner (assigned analyst)
├─ Created time (when incident created)
├─ Alert count (number of alerts)
├─ Entities (quick preview: users, IPs, hosts)
└─ Tags (custom labels)

Bulk Actions (Select Multiple Incidents):
├─ Assign: Bulk assignment to analyst
├─ Change severity: Increase/decrease severity
├─ Add tags: Bulk tagging ("Reviewed", "Escalated")
├─ Close: Bulk closure (for false positives)
└─ Export: Export to CSV (reporting)

Incident Details Page (Click Incident):
─────────────────────────────────────────
Top Actions:
├─ Assign: Assign to analyst
├─ Change severity: Adjust severity
├─ Change status: New → Active → Closed
├─ Add tags: Apply labels
├─ Run playbook: Execute automation (manual trigger)
├─ Create task: Break into sub-tasks
└─ Close incident: Mark as resolved

Tabs:
1️⃣ Overview
   - Summary: Incident details, severity, entities
   - Description: Auto-generated or custom
   - Investigation: Quick links to logs, queries

2️⃣ Alerts
   - List of alerts: Individual alert details
   - Alert details: Click to see raw alert data

3️⃣ Entities
   - Entity list: All mapped entities (users, IPs, hosts)
   - Entity details: Click to see entity timeline, properties
   - Investigation graph: Visual relationships

4️⃣ Evidence
   - Events: Raw log events (linked to incident)
   - Timeline: Chronological view
   - Files/URLs: Associated files, URLs

5️⃣ Investigation
   - Investigation graph: Visual attack chain
   - Timeline: Event sequence
   - Queries: Saved investigation queries

6️⃣ Comments
   - Analyst notes: Investigation findings
   - Team collaboration: Internal communication
   - Audit trail: Who did what, when

7️⃣ History
   - Change log: Status changes, assignments
   - Actions: Playbooks run, manual actions
   - Audit: Complete incident history

8️⃣ Similar incidents
   - Related: Incidents with same entities
   - Historical: Past incidents (same pattern)
   - Learning: How were similar incidents resolved?

Actions Menu (Right Panel):
├─ Assign
├─ Change severity
├─ Change status
├─ Add tags
├─ Run playbook (manual)
├─ Create task
├─ Close incident
└─ Export (JSON, CSV)
```

**🎯 Exam Tip:**
- **Incident**: Grouped alerts, investigation workflow, assigned to analyst
- **Lifecycle**: New → Active → Closed (with classification: TP, FP, BP, Undetermined)
- **Severity**: Informational, Low, Medium, High, Critical (drives prioritization)
- **Status**: New (unreviewed), Active (under investigation), Closed (resolved)
- **Triage**: Quick assessment (30s), context gathering (2-3 min), classification (1-2 min), prioritization, assignment
- **MTTT**: Mean Time to Triage (<15 min target)
- **Properties**: Title, severity, status, owner, entities, alerts, evidence, comments, tags
- **Portal**: Sentinel → Incidents (filtering, bulk actions, incident details page)

---

## 17. Incident Investigation

### 17.1 Investigation Process

**Systematic Approach to Incident Investigation:**

```
Investigation Steps:

1️⃣ Scope Definition (5-10 minutes)
   ├─ What: What happened? (Read alerts, description)
   ├─ Who: Who's affected? (Users, devices)
   ├─ When: When did it happen? (Timeline)
   ├─ Where: Where? (Locations, IPs, devices)
   └─ How: How did it happen? (Attack vector)

2️⃣ Evidence Collection (15-30 minutes)
   ├─ Log analysis: Query relevant logs (KQL)
   ├─ Entity investigation: User/device activities
   ├─ Threat intelligence: IoC lookups (malicious IPs, domains)
   ├─ Historical analysis: Past incidents (same entities)
   └─ External sources: WHOIS, VirusTotal, abuse databases

3️⃣ Root Cause Analysis (10-20 minutes)
   ├─ Initial access: How did attacker get in? (phishing, brute force)
   ├─ Persistence: Did attacker establish persistence? (backdoors, scheduled tasks)
   ├─ Lateral movement: Did attacker move laterally? (RDP, PSExec)
   ├─ Data exfiltration: Was data stolen? (large file transfers)
   └─ Impact assessment: What's the damage? (scope, severity)

4️⃣ Attack Chain Reconstruction (5-10 minutes)
   ├─ MITRE ATT&CK: Map to tactics/techniques
   ├─ Timeline: Chronological event sequence
   ├─ Kill chain: Cyber Kill Chain stages
   └─ Visualization: Investigation graph (entity relationships)

5️⃣ Documentation (Throughout Investigation)
   ├─ Comments: Add findings to incident
   ├─ Evidence: Link events, logs, screenshots
   ├─ Actions: Document actions taken
   └─ Recommendations: Next steps, follow-up tasks

Investigation Framework (SANS):
┌─────────────────────────────────────────────────────────┐
│ Preparation → Identification → Containment → Eradication│
│ → Recovery → Lessons Learned                            │
└─────────────────────────────────────────────────────────┘

We're focusing on: Identification + Containment (Investigation phase)
```

### 17.2 KQL Investigation Queries

**Common Investigation Queries:**

**Query 1: User Activity Timeline**

```kql
// See all activities by suspicious user (last 7 days)

let SuspiciousUser = "john@contoso.com";
let TimeRange = 7d;

// Sign-ins
SigninLogs
| where TimeGenerated > ago(TimeRange)
| where UserPrincipalName == SuspiciousUser
| project 
    TimeGenerated,
    Activity = "Sign-in",
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    ResultType,
    Details = strcat("Sign-in from ", Location, " via ", AppDisplayName)
| union (
    // File activities (Office 365)
    OfficeActivity
    | where TimeGenerated > ago(TimeRange)
    | where UserId == SuspiciousUser
    | project 
        TimeGenerated,
        Activity = Operation,
        UserPrincipalName = UserId,
        IPAddress = ClientIP,
        Location = "",
        AppDisplayName = "",
        ResultType = "",
        Details = strcat(Operation, " on ", OfficeObjectId)
  )
| union (
    // Email activities
    EmailEvents
    | where TimeGenerated > ago(TimeRange)
    | where RecipientEmailAddress == SuspiciousUser or SenderFromAddress == SuspiciousUser
    | project 
        TimeGenerated,
        Activity = "Email",
        UserPrincipalName = SuspiciousUser,
        IPAddress = "",
        Location = "",
        AppDisplayName = "",
        ResultType = DeliveryAction,
        Details = strcat("Email: ", Subject, " (", EmailDirection, ")")
  )
| sort by TimeGenerated desc
| project TimeGenerated, Activity, Details, IPAddress, Location, ResultType
```

**Query 2: Device Activity Investigation**

```kql
// See all activities on suspicious device (last 24 hours)

let SuspiciousDevice = "DESKTOP-123";
let TimeRange = 24h;

// Process creation (Windows)
SecurityEvent
| where TimeGenerated > ago(TimeRange)
| where Computer == SuspiciousDevice
| where EventID == 4688  // Process creation
| project 
    TimeGenerated,
    Computer,
    Activity = "Process Creation",
    Process,
    CommandLine,
    Account,
    Details = strcat("Process: ", Process, " | User: ", Account)
| union (
    // Network connections (MDE)
    DeviceNetworkEvents
    | where TimeGenerated > ago(TimeRange)
    | where DeviceName == SuspiciousDevice
    | project 
        TimeGenerated,
        Computer = DeviceName,
        Activity = "Network Connection",
        Process = InitiatingProcessFileName,
        CommandLine = "",
        Account = InitiatingProcessAccountName,
        Details = strcat("Connection to ", RemoteIP, ":", RemotePort)
  )
| union (
    // File events (MDE)
    DeviceFileEvents
    | where TimeGenerated > ago(TimeRange)
    | where DeviceName == SuspiciousDevice
    | project 
        TimeGenerated,
        Computer = DeviceName,
        Activity = ActionType,
        Process = InitiatingProcessFileName,
        CommandLine = "",
        Account = InitiatingProcessAccountName,
        Details = strcat(ActionType, ": ", FileName, " in ", FolderPath)
  )
| sort by TimeGenerated desc
| take 100  // Limit to 100 most recent events
```

**Query 3: Lateral Movement Detection**

```kql
// Detect lateral movement (RDP, PSExec, WMI from suspicious host)

let SuspiciousHost = "DESKTOP-123";
let TimeRange = 7d;

// RDP connections (Event ID 4624, Logon Type 10)
SecurityEvent
| where TimeGenerated > ago(TimeRange)
| where Computer == SuspiciousHost or IpAddress == SuspiciousHost
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RemoteInteractive (RDP)
| project 
    TimeGenerated,
    SourceHost = Computer,
    TargetHost = WorkstationName,
    Account,
    IpAddress,
    Activity = "RDP Connection",
    Details = strcat("RDP from ", Computer, " to ", WorkstationName, " by ", Account)
| union (
    // PSExec usage (Event ID 7045 - Service installation)
    SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where Computer == SuspiciousHost
    | where EventID == 7045  // Service installed
    | where ServiceFileName has "psexe"
    | project 
        TimeGenerated,
        SourceHost = Computer,
        TargetHost = Computer,
        Account,
        IpAddress,
        Activity = "PSExec",
        Details = strcat("PSExec service installed on ", Computer)
  )
| union (
    // WMI usage (Event ID 4688 - wmic.exe)
    SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where Computer == SuspiciousHost
    | where EventID == 4688
    | where Process has "wmic.exe"
    | where CommandLine has "/node:"  // Remote WMI
    | project 
        TimeGenerated,
        SourceHost = Computer,
        TargetHost = extract(@"/node:(\S+)", 1, CommandLine),
        Account,
        IpAddress,
        Activity = "WMI Remote",
        Details = strcat("WMI command to ", extract(@"/node:(\S+)", 1, CommandLine))
  )
| sort by TimeGenerated asc  // Chronological order (see attack progression)
```

**Query 4: Data Exfiltration Detection**

```kql
// Detect potential data exfiltration (large file transfers, external sharing)

let SuspiciousUser = "john@contoso.com";
let TimeRange = 24h;
let SizeThresholdMB = 100;  // Alert on files >100 MB

// Large file downloads (Office 365)
OfficeActivity
| where TimeGenerated > ago(TimeRange)
| where UserId == SuspiciousUser
| where Operation == "FileDownloaded"
| extend FileSizeMB = toint(Size) / 1024 / 1024
| where FileSizeMB > SizeThresholdMB
| project 
    TimeGenerated,
    User = UserId,
    Activity = Operation,
    FileName = SourceFileName,
    FileSizeMB,
    Site = SiteUrl,
    ClientIP,
    Details = strcat("Downloaded ", FileSizeMB, " MB file: ", SourceFileName)
| union (
    // External file sharing
    OfficeActivity
    | where TimeGenerated > ago(TimeRange)
    | where UserId == SuspiciousUser
    | where Operation == "SharingSet"
    | where TargetUserOrGroupType == "Guest"  // External user
    | project 
        TimeGenerated,
        User = UserId,
        Activity = Operation,
        FileName = SourceFileName,
        FileSizeMB = 0,
        Site = SiteUrl,
        ClientIP,
        Details = strcat("Shared file externally: ", SourceFileName, " with ", TargetUserOrGroupName)
  )
| union (
    // Large email attachments sent
    EmailAttachmentInfo
    | where TimeGenerated > ago(TimeRange)
    | where SenderFromAddress == SuspiciousUser
    | where FileSize > (SizeThresholdMB * 1024 * 1024)
    | project 
        TimeGenerated,
        User = SenderFromAddress,
        Activity = "Email Attachment",
        FileName,
        FileSizeMB = FileSize / 1024 / 1024,
        Site = "",
        ClientIP = "",
        Details = strcat("Sent ", FileSizeMB, " MB attachment: ", FileName)
  )
| sort by TimeGenerated desc
```

**Query 5: Malware Indicators**

```kql
// Investigate malware indicators (processes, files, registry, network)

let SuspiciousHost = "DESKTOP-123";
let TimeRange = 7d;

// Suspicious processes
SecurityEvent
| where TimeGenerated > ago(TimeRange)
| where Computer == SuspiciousHost
| where EventID == 4688  // Process creation
| where CommandLine has_any (
    "-enc",              // Encoded PowerShell
    "IEX",               // Invoke-Expression
    "DownloadString",    // Download from internet
    "mimikatz",          // Credential dumping
    "procdump",          // Memory dumping
    "psexec",            // Lateral movement
    "wmic"               // Remote execution
  )
| project 
    TimeGenerated,
    Computer,
    Activity = "Suspicious Process",
    Process,
    CommandLine,
    Account,
    ParentProcessName,
    Details = strcat("Process: ", Process, " | Command: ", CommandLine)
| union (
    // Suspicious file creation (MDE)
    DeviceFileEvents
    | where TimeGenerated > ago(TimeRange)
    | where DeviceName == SuspiciousHost
    | where ActionType == "FileCreated"
    | where FolderPath has_any (
        "\\Temp\\",
        "\\AppData\\Local\\Temp\\",
        "\\Windows\\Temp\\"
      )
    | where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
    | project 
        TimeGenerated,
        Computer = DeviceName,
        Activity = "Suspicious File",
        Process = InitiatingProcessFileName,
        CommandLine = "",
        Account = InitiatingProcessAccountName,
        ParentProcessName = "",
        Details = strcat("File created in Temp: ", FileName, " at ", FolderPath)
  )
| union (
    // Suspicious registry modifications (MDE)
    DeviceRegistryEvents
    | where TimeGenerated > ago(TimeRange)
    | where DeviceName == SuspiciousHost
    | where RegistryKey has_any (
        "\\Run",           // Persistence
        "\\RunOnce",       // Persistence
        "\\Services",      // Service creation
        "\\Winlogon"       // Login script
      )
    | project 
        TimeGenerated,
        Computer = DeviceName,
        Activity = "Registry Modification",
        Process = InitiatingProcessFileName,
        CommandLine = "",
        Account = InitiatingProcessAccountName,
        ParentProcessName = "",
        Details = strcat("Registry key modified: ", RegistryKey, " = ", RegistryValueName)
  )
| sort by TimeGenerated asc
```

### 17.3 Entity Investigation

**Deep Dive on Entities:**

```
Entity Investigation Workflow:

Step 1: Click Entity in Incident
─────────────────────────────────────────
Portal: Incident details → Entities tab → Click entity (user, IP, host)

Entity Page Opens:
├─ Entity details: Properties (name, type, tags)
├─ Related alerts: All alerts involving this entity
├─ Timeline: All activities (chronological)
├─ Investigation graph: Visual relationships
└─ Quick actions: Run queries, create watchlist

Step 2: Review Entity Timeline
─────────────────────────────────────────
Timeline shows:
├─ Sign-ins: All authentication events
├─ Activities: File access, email, process execution
├─ Alerts: Security alerts involving this entity
├─ Incidents: Past incidents (same entity)
└─ Time range: Adjustable (24h, 7d, 30d)

Use Cases:
✅ Compromised user: See all activities after compromise
✅ Malicious IP: See all connections from/to this IP
✅ Infected device: See malware execution timeline

Step 3: Investigation Graph (Entity Relationships)
─────────────────────────────────────────
Graph shows:
├─ User → Signed in from → IP
├─ User → Accessed → File
├─ File → Created on → Host
├─ Host → Connected to → Malicious IP
└─ Relationships: Visual attack chain

Benefits:
✅ See full attack chain (not isolated events)
✅ Identify pivot points (where to investigate next)
✅ Discover related entities (lateral movement, C2)

Step 4: Run Investigation Queries
─────────────────────────────────────────
Built-in Investigation Queries:
├─ Account queries:
│  ├─ All activities by this account
│  ├─ Failed sign-ins
│  ├─ Rare sign-in locations
│  └─ Group membership changes
│
├─ Host queries:
│  ├─ All processes created
│  ├─ Network connections
│  ├─ File modifications
│  └─ Scheduled tasks created
│
└─ IP queries:
   ├─ All connections from/to this IP
   ├─ Threat intelligence lookup (malicious?)
   ├─ WHOIS lookup (who owns this IP?)
   └─ Geolocation (where is this IP?)

Action: Click "Run query" → Results displayed → Investigate further

Step 5: Check UEBA (User/Entity Risk Score)
─────────────────────────────────────────
If UEBA enabled:
├─ Risk score: 0-100 (confidence of compromise)
├─ Risk reasons: Why high risk? (anomalies detected)
├─ Peer comparison: Compare to similar users
└─ Historical: Risk score over time

High risk score (>70) → Strong indicator of compromise

Step 6: Threat Intelligence Lookup
─────────────────────────────────────────
For IPs, domains, file hashes:
├─ TI tables: Check ThreatIntelIndicators
├─ External: VirusTotal, AlienVault OTX, abuse databases
├─ Reputation: Known malicious? (C2, malware host)
└─ Context: Threat actor attribution, campaigns

Query:
ThreatIntelIndicators
| where NetworkIP == "203.0.113.50" or DomainName == "evil.com"
| where Active == true
| project ThreatType, Description, ConfidenceScore, Tags
```

### 17.4 Evidence Collection Best Practices

**Building a Strong Case:**

```
Evidence Documentation:

1️⃣ Screenshots
   ├─ Capture: Key findings, alerts, logs
   ├─ Annotate: Highlight important details
   ├─ Attach: To incident comments
   └─ Use: For reporting, management briefings

2️⃣ Log Exports
   ├─ Export: Relevant log entries (CSV, JSON)
   ├─ Preserve: For forensics, legal proceedings
   ├─ Attach: To incident or external storage
   └─ Use: Chain of custody, detailed analysis

3️⃣ Query Results
   ├─ Save: KQL queries used in investigation
   ├─ Document: Why this query? What did it find?
   ├─ Link: Reference in incident comments
   └─ Use: Reproducibility, peer review

4️⃣ External Evidence
   ├─ VirusTotal: Malware analysis reports
   ├─ WHOIS: Domain/IP ownership
   ├─ Abuse databases: Malicious IP/domain lists
   └─ Vendor reports: Threat intelligence, advisories

5️⃣ Timeline Reconstruction
   ├─ Create: Detailed timeline (spreadsheet or tool)
   ├─ Include: All events (chronological order)
   ├─ Annotate: Actions, findings, decisions
   └─ Use: Root cause analysis, reporting

Evidence Checklist:
✅ Who: All entities involved (users, IPs, hosts, files)
✅ What: What happened (actions, events)
✅ When: Exact timestamps (timezone-aware)
✅ Where: Locations (IPs, physical locations, systems)
✅ How: Attack vector, techniques (MITRE ATT&CK)
✅ Why: Motivation (if known), impact assessment
✅ Actions: What was done in response (remediation)

Chain of Custody:
├─ Preserve: Original log entries (no tampering)
├─ Hash: File hashes (verify integrity)
├─ Document: Who accessed evidence, when, why
└─ Store: Secure storage (restricted access)
```

**🎯 Exam Tip:**
- **Investigation process**: Scope definition → Evidence collection → Root cause analysis → Attack chain reconstruction → Documentation
- **KQL queries**: User timeline, device activity, lateral movement, data exfiltration, malware indicators
- **Entity investigation**: Timeline (all activities), investigation graph (relationships), built-in queries, UEBA (risk score), TI lookup
- **Evidence**: Screenshots, log exports, query results, external evidence, timeline reconstruction
- **Best practices**: Document findings (comments), preserve evidence (chain of custody), use investigation graph
- **MITRE ATT&CK**: Map attack to tactics/techniques (Initial Access, Execution, Persistence, etc.)

---

## 18. Investigation Graph & Timeline

### 18.1 Investigation Graph

**Visual Attack Chain Representation:**

```
What is Investigation Graph?
- Visual representation of entity relationships
- Automatic generation from entity mapping
- Interactive exploration (click to expand)
- Export for reporting, documentation

Graph Components:

1️⃣ Entities (Nodes)
   ├─ Accounts: Users involved (circle icon)
   ├─ Hosts: Devices (computer icon)
   ├─ IPs: IP addresses (globe icon)
   ├─ Files: Files involved (file icon)
   ├─ Processes: Processes executed (gear icon)
   └─ More: URLs, mailboxes, cloud apps, etc.

2️⃣ Relationships (Edges)
   ├─ User → Signed in from → IP
   ├─ User → Accessed → File
   ├─ File → Created on → Host
   ├─ Host → Connected to → IP
   ├─ Process → Created → File
   └─ User → Sent email to → Mailbox

3️⃣ Attributes
   ├─ Color: Entity risk (red = high risk, green = normal)
   ├─ Size: Activity volume (bigger = more activities)
   ├─ Thickness: Relationship strength (thicker = more connections)
   └─ Icon: Entity type (user, device, IP, file)

Example Graph (Phishing Attack):

     ┌─────────────┐
     │Attacker Email│
     │sender@evil.com│
     └──────┬──────┘
            │ sent email to
            ▼
     ┌─────────────┐
     │   Victim    │
     │john@contoso │
     └──────┬──────┘
            │ clicked URL
            ▼
     ┌─────────────┐
     │Malicious URL│
     │https://evil │
     └──────┬──────┘
            │ downloaded
            ▼
     ┌─────────────┐
     │ Malware File│
     │ payload.exe │
     └──────┬──────┘
            │ executed on
            ▼
     ┌─────────────┐
     │    Host     │
     │ DESKTOP-123 │
     └──────┬──────┘
            │ connected to
            ▼
     ┌─────────────┐
     │   C2 Server │
     │203.0.113.50 │
     └─────────────┘

Benefits:
✅ Visual clarity: See full attack chain (not text logs)
✅ Relationship discovery: Find hidden connections
✅ Pivot points: Identify where to investigate next
✅ Communication: Easy to explain to management
✅ Pattern recognition: Similar attacks have similar graphs
```

### 18.2 Graph Exploration

**Interactive Investigation:**

```
Portal: Incident → Investigation → Investigation graph

Actions:

1️⃣ Expand Entity
   ├─ Right-click entity → "Explore related entities"
   ├─ Shows: All related entities (not shown initially)
   ├─ Use: Deep dive on specific entity
   └─ Example: Expand user → See all IPs, hosts, files

2️⃣ Filter Graph
   ├─ By entity type: Show only users, or only IPs
   ├─ By time range: Show entities from last 24h
   ├─ By risk: Show only high-risk entities
   └─ Use: Reduce noise, focus on relevant entities

3️⃣ Highlight Path
   ├─ Select: Start entity + End entity
   ├─ Highlight: Shortest path between them
   ├─ Use: See attack progression (initial access → data exfiltration)
   └─ Example: Attacker IP → Victim user → Sensitive file

4️⃣ Entity Details
   ├─ Click entity → Details panel opens
   ├─ Shows: Entity properties, activities, alerts
   ├─ Actions: Run queries, add to watchlist
   └─ Use: Quick investigation without leaving graph

5️⃣ Export Graph
   ├─ Export: PNG, SVG, JSON
   ├─ Use: Reports, presentations, documentation
   └─ Share: With team, management, external parties

6️⃣ Run Queries from Graph
   ├─ Right-click entity → "Run investigation query"
   ├─ Queries: Pre-built investigation queries
   ├─ Results: Displayed in panel (or new tab)
   └─ Use: Quick evidence collection

Graph Layout Options:
├─ Hierarchical: Top-down (initial access → final impact)
├─ Radial: Central entity, related entities around
├─ Force-directed: Entities repel/attract (organic layout)
└─ Custom: Drag entities manually (custom arrangement)
```

### 18.3 Timeline

**Chronological Event Visualization:**

```
What is Timeline?
- Chronological view of all events in incident
- All entities combined (unified timeline)
- Filterable, searchable, exportable

Timeline View:
Portal: Incident → Investigation → Timeline

Timeline Components:

1️⃣ Time Axis (Horizontal)
   ├─ Start: First event in incident
   ├─ End: Last event (or now)
   ├─ Zoom: Adjustable (zoom in/out)
   └─ Markers: Key events (alerts, high-risk activities)

2️⃣ Event Tracks (Vertical Lanes)
   ├─ By entity: One track per entity
   ├─ Example:
   │  ├─ Track 1: User john@contoso.com (sign-ins, file access)
   │  ├─ Track 2: Host DESKTOP-123 (processes, network)
   │  ├─ Track 3: IP 203.0.113.50 (connections)
   │  └─ Track 4: File payload.exe (creation, execution)
   └─ Color-coded: By activity type (sign-in = blue, process = red)

3️⃣ Events (Points on Timeline)
   ├─ Icon: Activity type (sign-in, process, file, network)
   ├─ Size: Importance (larger = more significant)
   ├─ Color: Risk level (red = high risk, green = normal)
   └─ Click: Show event details

Example Timeline (Ransomware Attack):

Time Axis: ─────────────────────────────────────────────>
           10:00 AM        11:00 AM        12:00 PM

User john@:
  10:05 AM: Sign-in (office IP) [Blue dot]
  10:30 AM: Email received (phishing) [Yellow dot]
  10:31 AM: URL clicked [Orange dot]

Host DESKTOP:
  10:32 AM: payload.exe downloaded [Red dot]
  10:33 AM: payload.exe executed [Red dot]
  10:35 AM: Mass file deletion started [Critical Red]

Network:
  10:34 AM: Connection to 203.0.113.50 (C2) [Red dot]
  10:36 AM: Large data upload [Red dot]

Timeline Analysis:
├─ 10:05 AM: Initial access (legitimate sign-in)
├─ 10:30 AM: Phishing email arrives
├─ 10:31 AM: User clicks malicious link
├─ 10:32 AM: Malware downloaded
├─ 10:33 AM: Malware executed
├─ 10:34 AM: C2 communication established
├─ 10:35 AM: Ransomware encryption starts
└─ 10:36 AM: Data exfiltration (double extortion)

Time to detect: 10:36 AM (alert fires)
Dwell time: 31 minutes (initial access → detection)
```

### 18.4 Timeline Features

**Advanced Timeline Capabilities:**

```
1️⃣ Filtering
   ├─ By entity: Show only user john@contoso.com
   ├─ By activity type: Show only sign-ins
   ├─ By time range: Show 10:00-11:00 AM
   ├─ By risk: Show only high-risk events
   └─ By source: Show only MDE events

2️⃣ Search
   ├─ Search: Event details (e.g., "payload.exe")
   ├─ Highlight: Matching events on timeline
   ├─ Jump: Navigate to event
   └─ Use: Find specific events quickly

3️⃣ Annotations
   ├─ Add: Custom annotations (notes, markers)
   ├─ Example: "Initial access", "Containment started"
   ├─ Use: Document investigation milestones
   └─ Share: Annotations saved with incident

4️⃣ Playback
   ├─ Play: Events play in sequence (animation)
   ├─ Speed: Adjustable (faster/slower)
   ├─ Use: Understand attack progression (visual)
   └─ Present: Great for management briefings

5️⃣ Export Timeline
   ├─ Export: PNG, CSV, JSON
   ├─ Use: Reports, presentations
   └─ Share: With team, management

6️⃣ Correlation
   ├─ Automatic: Timeline correlates events across sources
   ├─ Example: Sign-in (Entra ID) + Process (MDE) + Network (Firewall)
   ├─ Benefit: Unified view (no manual correlation needed)
   └─ Sources: Sentinel, Defender XDR, third-party

7️⃣ Gaps Detection
   ├─ Identify: Large time gaps between events
   ├─ Reason: Missing logs? Attacker hiding? Legitimate quiet period?
   ├─ Action: Investigate gaps (query for missing events)
   └─ Use: Ensure complete visibility
```

### 18.5 Using Graph & Timeline Together

**Combined Investigation Workflow:**

```
Workflow:

Step 1: Start with Timeline
─────────────────────────────────────────
- Review: All events chronologically
- Identify: Key events (initial access, malware execution, C2)
- Note: Time gaps, unusual patterns

Step 2: Switch to Graph
─────────────────────────────────────────
- Visualize: Entity relationships
- Identify: Attack chain (initial access → final impact)
- Pivot: Focus on high-risk entities

Step 3: Drill Down on Graph
─────────────────────────────────────────
- Expand: High-risk entities
- Explore: Related entities (not shown initially)
- Run: Investigation queries (from graph)

Step 4: Verify in Timeline
─────────────────────────────────────────
- Check: Timeline for detailed event sequence
- Confirm: Attack chain hypothesis
- Document: Key events, timestamps

Step 5: Export & Report
─────────────────────────────────────────
- Export: Graph (PNG) + Timeline (CSV)
- Create: Executive summary (visual + chronological)
- Share: With team, management, CISO

Example: Phishing Investigation

Timeline View:
10:30 AM: Email received → 10:31 AM: URL clicked → 10:32 AM: File downloaded
→ 10:33 AM: File executed → 10:34 AM: C2 connection

Graph View:
Attacker Email → Victim User → Malicious URL → Malware File → Host → C2 Server

Together:
- Timeline: Shows WHEN (sequence, timing)
- Graph: Shows WHO, WHAT, WHERE (entities, relationships)
- Combined: Complete attack story (timeline + attack chain)

Benefits:
✅ Timeline: Understand sequence (what happened when)
✅ Graph: Understand relationships (who did what)
✅ Together: Complete picture (time + relationships)
```

**🎯 Exam Tip:**
- **Investigation graph**: Visual representation of entity relationships (nodes + edges)
- **Entities (nodes)**: Accounts, hosts, IPs, files, processes, URLs
- **Relationships (edges)**: Sign-in from, accessed, created, connected to
- **Graph actions**: Expand entity, filter, highlight path, run queries, export
- **Timeline**: Chronological event view, all entities combined, filterable, searchable
- **Timeline features**: Time axis (horizontal), event tracks (vertical lanes), events (points), playback, annotations
- **Combined use**: Timeline (WHEN), Graph (WHO/WHAT/WHERE), Together (complete story)
- **Export**: Graph (PNG, SVG), Timeline (CSV, JSON) for reporting

---

## 19. Automation Rules

### 19.1 What are Automation Rules?

**Incident-Triggered Workflows:**

```
Automation Rule:
- Definition: If-then logic triggered by incidents
- Purpose: Automate repetitive SOC tasks
- Trigger: Incident created or updated
- Action: Change properties, assign, run playbook, etc.

Automation Rule vs Playbook:
┌────────────────────────────────────────────────────────┐
│ Feature          | Automation Rule | Playbook (Logic App)│
├────────────────────────────────────────────────────────┤
│ Complexity       | Simple          | Complex (any logic) │
│ Actions          | Limited         | Unlimited (1000+ connectors)│
│ Conditions       | Basic if-then   | Advanced if/else, loops│
│ Use Case         | Incident mgmt   | Response actions    │
│ Configuration    | Portal (wizard) | Logic Apps Designer │
│ Cost             | Included (free) | Per execution (~$0.000025)│
└────────────────────────────────────────────────────────┘

Example Use Cases:

Automation Rules (Simple):
├─ Auto-assign incidents to analysts (by severity, entity)
├─ Add tags automatically ("VIP", "Production")
├─ Change severity (increase for VIP users)
├─ Trigger playbook (when specific condition met)
└─ Close incidents (known false positives)

Playbooks (Complex):
├─ Block IP on firewall (API call)
├─ Disable user account in Entra ID
├─ Isolate device via MDE
├─ Send email/Teams notification
├─ Create ServiceNow ticket
└─ Complex multi-step workflows (enrich → analyze → respond)
```

### 19.2 Automation Rule Components

**Building Blocks:**

```
Automation Rule Structure:

1️⃣ Trigger (When to Run)
   ├─ Incident created: When new incident created
   ├─ Incident updated: When incident properties change
   └─ Both: Run on create or update

2️⃣ Conditions (If...)
   ├─ Analytics rule: Specific rule(s) that triggered incident
   ├─ Incident provider: Sentinel, Defender XDR, Defender for Cloud
   ├─ Severity: Informational, Low, Medium, High, Critical
   ├─ Status: New, Active, Closed
   ├─ Title: Contains specific text
   ├─ Description: Contains specific text
   ├─ Tags: Has specific tag(s)
   ├─ Entities: Specific entity types (Account, Host, IP)
   ├─ Alert product: MDE, MDO, MDCA, etc.
   └─ Custom conditions: Multiple conditions (AND/OR logic)

3️⃣ Actions (Then...)
   ├─ Assign incident: To analyst or team
   ├─ Change severity: Increase/decrease severity
   ├─ Change status: New → Active, or Active → Closed
   ├─ Add tags: Apply labels
   ├─ Run playbook: Execute Logic App workflow
   └─ Add comment: Document automation action

4️⃣ Expiration (Optional)
   ├─ Expiration date: Rule automatically disables after date
   ├─ Use: Temporary rules (during incident, migration, testing)
   └─ Example: "Suppress alerts during maintenance (Oct 1-3)"

5️⃣ Order (Priority)
   ├─ Order number: 1, 2, 3, etc. (lower = higher priority)
   ├─ Execution: Rules run in order (1st, 2nd, 3rd)
   ├─ Stop processing: Option to stop after this rule
   └─ Use: Ensure correct rule precedence

Example Automation Rule:
┌────────────────────────────────────────────────────────┐
│ Rule Name: "Auto-assign High Severity to Tier 2"      │
│ Trigger: Incident created                              │
│ Conditions:                                            │
│   - Severity: High or Critical                         │
│   - Status: New                                        │
│   - Analytics rule: "Brute Force", "Ransomware", ...  │
│ Actions:                                               │
│   - Assign to: tier2-soc@contoso.com                  │
│   - Change status: New → Active                        │
│   - Add tag: "Escalated"                               │
│   - Add comment: "Auto-assigned to Tier 2 (high sev)" │
│ Order: 1 (run first)                                   │
└────────────────────────────────────────────────────────┘
```

### 19.3 Common Automation Rule Examples

**Real-World Automation Rules:**

**Example 1: Auto-Assign by Severity**

```
Rule: Assign incidents based on severity

Trigger: Incident created
Conditions:
├─ Severity: Critical OR High
└─ Status: New

Actions:
├─ Assign to: senior-analysts@contoso.com
├─ Change status: New → Active
├─ Add tag: "High Priority"
└─ Add comment: "Auto-assigned to senior analysts (critical/high severity)"

Order: 1

Result: Critical/High incidents immediately assigned to senior team
```

**Example 2: VIP User Escalation**

```
Rule: Escalate incidents involving VIP users

Trigger: Incident created
Conditions:
├─ Entity type: Account
├─ Account: Contains "ceo@", "cfo@", "ciso@" (custom property)
└─ OR Account: In "VIP Users" watchlist

Actions:
├─ Change severity: Increase by 1 level (e.g., Medium → High)
├─ Assign to: vip-response-team@contoso.com
├─ Add tag: "VIP User"
├─ Add comment: "VIP user involved - escalated"
└─ Run playbook: "Notify-CISO" (send urgent email)

Order: 2

Result: VIP incidents escalated immediately with CISO notification
```

**Example 3: False Positive Auto-Closure**

```
Rule: Close known false positives automatically

Trigger: Incident created
Conditions:
├─ Analytics rule: "Legacy App Logon Failure" (specific noisy rule)
├─ Entity Host: Contains "legacy-server-" (specific servers)
└─ Severity: Low

Actions:
├─ Change status: New → Closed
├─ Classification: False Positive
├─ Comment: "Auto-closed - known issue with legacy app (Ticket #12345)"
└─ Add tag: "Auto-Closed"

Order: 10 (run after other rules)

Result: Known FPs closed immediately, reducing analyst workload
```

**Example 4: Production Server Priority**

```
Rule: Prioritize production server incidents

Trigger: Incident created
Conditions:
├─ Entity type: Host
├─ Host: Contains "prod-" or "production-"
└─ Severity: Medium OR High

Actions:
├─ Change severity: Increase by 1 level (Medium → High, High → Critical)
├─ Add tag: "Production Server"
├─ Assign to: production-support@contoso.com
└─ Run playbook: "Notify-Operations-Team"

Order: 3

Result: Production incidents prioritized, operations team notified
```

**Example 5: Trigger Playbook for Automated Response**

```
Rule: Auto-block malicious IPs

Trigger: Incident created
Conditions:
├─ Analytics rule: "Connection to Malicious IP" (TI match)
├─ Severity: High OR Critical
├─ Entity type: IP
└─ TI Confidence: >80 (high confidence malicious)

Actions:
├─ Run playbook: "Block-IP-on-Firewall" (automated containment)
├─ Add tag: "Auto-Blocked"
├─ Add comment: "Malicious IP auto-blocked on firewall"
└─ Assign to: analyst-on-call@contoso.com (for investigation)

Order: 1 (run first - immediate containment)

Result: Malicious IPs blocked automatically within minutes
```

**Example 6: Geo-based Assignment**

```
Rule: Assign based on sign-in location (follow-the-sun)

Trigger: Incident created
Conditions:
├─ Entity type: IP
├─ IP geolocation: Country in ("United States", "Canada", "Mexico")
└─ Time: 8 AM - 6 PM local time (business hours)

Actions:
├─ Assign to: americas-soc@contoso.com
└─ Add comment: "Assigned to Americas SOC (business hours)"

Order: 5

Alternative Rules:
- EMEA SOC (Europe, Middle East, Africa)
- APAC SOC (Asia-Pacific)

Result: Follow-the-sun coverage (incidents assigned to active SOC)
```

### 19.4 Automation Rule Best Practices

**Design & Maintenance:**

```
Best Practices:

1️⃣ Start Simple
   ✅ Begin: Simple rules (auto-assign, tagging)
   ✅ Test: Thoroughly before production
   ✅ Iterate: Add complexity gradually
   ❌ Avoid: Complex logic in automation rules (use playbooks)

2️⃣ Use Specific Conditions
   ✅ Specific: Target exact analytics rules, entities
   ❌ Generic: Avoid "All incidents" (too broad)
   
   Example:
   ✅ Good: "If rule = 'Brute Force' AND Severity = High"
   ❌ Bad: "If Severity = High" (too many incidents matched)

3️⃣ Order Matters
   ✅ Priority rules first: VIP, Critical severity (Order 1, 2, 3)
   ✅ General rules next: Normal assignment (Order 5, 10)
   ✅ Cleanup rules last: False positive closure (Order 100)
   ✅ Stop processing: Use when appropriate (prevent rule conflicts)

4️⃣ Document Rules
   ✅ Rule name: Descriptive (what it does)
   ✅ Description: Why this rule exists (business justification)
   ✅ Comments: In actions (audit trail)
   ✅ Tags: "Automation", "Tested", "Production"

5️⃣ Monitor Automation
   ✅ Metrics: Track automation rule executions (how many incidents automated?)
   ✅ Review: Monthly review (are rules still relevant?)
   ✅ Adjust: Tune conditions, actions based on feedback
   ✅ Disable: Old/obsolete rules (don't delete immediately)

6️⃣ Avoid Conflicts
   ⚠️ Problem: Multiple rules modifying same property
   
   Example Conflict:
   Rule 1: Assign to Tier 1 (Order 1)
   Rule 2: Assign to Tier 2 (Order 2)
   Result: Incident assigned to Tier 2 (Rule 2 overwrites Rule 1)
   
   Solution: Use "Stop processing" or mutually exclusive conditions

7️⃣ Test Before Production
   ✅ Test workspace: Create test incidents, verify rules
   ✅ Sandbox: Use disabled rules (test mode)
   ✅ Validation: Check rule logic, actions
   ✅ Rollback: Keep backup of rules (before changes)

8️⃣ Use Expiration for Temporary Rules
   ✅ Maintenance: "Suppress during maintenance window (Oct 1-3)"
   ✅ Incident: "Auto-escalate during active incident response"
   ✅ Testing: "Test new assignment logic (1 week trial)"
   ✅ Auto-disable: Rules expire automatically (cleanup)

Common Pitfalls:
❌ Too many automation rules (confusion, conflicts)
❌ Overly broad conditions (too many incidents matched)
❌ Lack of documentation (why does this rule exist?)
❌ No monitoring (rules broken, no one notices)
❌ Automation without human oversight (100% automation risky)

Recommended Limits:
├─ Automation rules: 10-20 per workspace (keep manageable)
├─ Actions per rule: 3-5 (keep simple)
├─ Playbook executions: Monitor costs (per execution charge)
└─ Review frequency: Monthly (ensure rules still relevant)
```

**🎯 Exam Tip:**
- **Automation rules**: Incident-triggered, simple if-then logic, automate SOC tasks
- **Trigger**: Incident created or updated
- **Conditions**: Analytics rule, severity, status, title, tags, entities (if...)
- **Actions**: Assign, change severity, change status, add tags, run playbook, add comment (then...)
- **Order**: Priority (lower number = higher priority), run in sequence
- **Use cases**: Auto-assign (severity, entity), VIP escalation, FP closure, trigger playbooks, geo-based assignment
- **Best practices**: Start simple, specific conditions, order matters, document, monitor, avoid conflicts, test first
- **Exam scenario**: "Automate incident assignment" → Use automation rule (not playbook)

---

## 20. Playbooks (Logic Apps)

### 20.1 Playbook Overview

**Automated Response Workflows:**

```
Playbook (Logic App):
- Definition: Workflow automation (Security Orchestration)
- Platform: Azure Logic Apps (serverless)
- Purpose: Automate complex response actions
- Trigger: Manual, incident-triggered (via automation rule), scheduled
- Actions: Unlimited (1,000+ connectors)

Playbook Architecture:

Trigger (When to Run)
↓
Actions (What to Do)
├─ Step 1: Get incident details
├─ Step 2: Enrich (threat intel, WHOIS, geolocation)
├─ Step 3: Analyze (if/else logic, loops)
├─ Step 4: Respond (block IP, disable user, isolate device)
├─ Step 5: Notify (email, Teams, ServiceNow)
└─ Step 6: Update incident (add comment, change status)

Common Playbook Scenarios:

1️⃣ Enrichment Playbooks
   ├─ Get IP geolocation (GeoIP API)
   ├─ Get WHOIS data (domain ownership)
   ├─ Query threat intelligence (VirusTotal, AlienVault)
   ├─ Get user risk score (UEBA)
   └─ Add enrichment to incident (comments)

2️⃣ Response Playbooks
   ├─ Block IP (firewall API: Palo Alto, Azure Firewall)
   ├─ Disable user (Entra ID API)
   ├─ Reset password (force password change)
   ├─ Isolate device (MDE API)
   ├─ Quarantine file (antivirus API)
   └─ Revoke user sessions (Entra ID)

3️⃣ Notification Playbooks
   ├─ Send email (to analyst, manager, CISO)
   ├─ Post to Teams channel (SOC team notification)
   ├─ Post to Slack (cross-team coordination)
   ├─ Create ServiceNow ticket (ITSM integration)
   ├─ Send SMS (PagerDuty, Twilio for urgent alerts)
   └─ Call webhook (custom integrations)

4️⃣ Investigation Playbooks
   ├─ Collect logs (export logs for forensics)
   ├─ Take memory dump (device forensics)
   ├─ Query user activity (Entra ID, Office 365)
   ├─ Check device compliance (Intune)
   └─ Run advanced hunting (MDE, Defender XDR)

5️⃣ Hybrid Playbooks (Enrichment + Response + Notification)
   ├─ Enrich incident (threat intel, geolocation)
   ├─ Analyze (if high confidence malicious)
   ├─ Respond (block IP, disable user)
   ├─ Notify (email SOC + CISO, create ticket)
   └─ Update incident (add comment, change status)
```

### 20.2 Playbook Components

**Building Blocks (Logic Apps):**

```
Playbook Structure:

1️⃣ Trigger (Required)
   ├─ Microsoft Sentinel Alert: Triggered by alert
   ├─ Microsoft Sentinel Incident: Triggered by incident
   ├─ HTTP Request: Webhook (external system calls playbook)
   ├─ Recurrence: Scheduled (run every X hours/days)
   └─ Manual: Manual execution from portal

2️⃣ Actions (Steps in Workflow)
   
   A. Sentinel Actions (Built-in):
   ├─ Get incident: Retrieve incident details
   ├─ Get entities: Extract entities (users, IPs, hosts)
   ├─ Update incident: Change properties (severity, status, owner)
   ├─ Add comment: Document playbook actions
   ├─ Add tags: Apply labels
   └─ Create task: Break into sub-tasks

   B. Entra ID (Azure AD) Actions:
   ├─ Get user: Retrieve user details (department, manager)
   ├─ Disable user: Disable account
   ├─ Reset password: Force password change
   ├─ Revoke sessions: Sign out all sessions
   ├─ Add user to group: Add to quarantine group
   └─ Remove user from group: Remove from access group

   C. Microsoft Defender Actions:
   ├─ MDE: Isolate device, run antivirus scan, collect investigation package
   ├─ MDO: Delete email, quarantine email, report phishing
   ├─ MDCA: Block cloud app, revoke app permissions
   └─ Defender XDR: Run automated investigation

   D. Communication Actions:
   ├─ Office 365 Outlook: Send email
   ├─ Microsoft Teams: Post message to channel
   ├─ Slack: Post message
   ├─ Twilio: Send SMS
   └─ PagerDuty: Create incident

   E. ITSM Actions:
   ├─ ServiceNow: Create incident, update ticket
   ├─ Jira: Create issue, add comment
   ├─ Zendesk: Create ticket
   └─ Custom: HTTP requests to any ticketing system

   F. Threat Intelligence Actions:
   ├─ VirusTotal: Query file hash, IP, domain
   ├─ AlienVault OTX: Query threat intel
   ├─ ThreatConnect: Query indicators
   ├─ MISP: Query threat sharing platform
   └─ Custom TI: HTTP requests to custom TI platforms

   G. Network Security Actions:
   ├─ Palo Alto Networks: Block IP, create address object
   ├─ Fortinet: Block IP, create firewall rule
   ├─ Cisco: Block IP, update ACL
   ├─ Azure Firewall: Add IP to deny list
   └─ Zscaler: Block URL, add to blocklist

   H. Control Flow (Logic):
   ├─ Condition (if/else): If severity = Critical, then...
   ├─ Switch (multi-way): Switch on entity type (Account, Host, IP)
   ├─ For each loop: Iterate over entities
   ├─ Until loop: Repeat until condition met
   ├─ Scope: Group actions (error handling)
   └─ Terminate: Stop playbook execution

   I. Data Operations:
   ├─ Parse JSON: Extract fields from JSON
   ├─ Compose: Create JSON, XML, text
   ├─ Filter array: Filter entities (e.g., only IPs)
   ├─ Select: Transform data (map fields)
   └─ Join: Concatenate arrays

   J. General Actions:
   ├─ HTTP: Call any REST API (custom integrations)
   ├─ Variables: Store temporary data
   ├─ Delay: Wait X seconds/minutes
   ├─ Terminate: Stop playbook (success/failure)
   └─ Run JavaScript: Custom logic (limited)

3️⃣ Connections (Authentication)
   ├─ Managed Identity: Playbook authenticates as Sentinel (recommended)
   ├─ OAuth: User grants permissions (Entra ID, Teams, etc.)
   ├─ API Key: Third-party services (VirusTotal, AlienVault)
   ├─ Username/Password: Legacy systems (not recommended)
   └─ Certificate: PKI-based authentication

4️⃣ Error Handling
   ├─ Run after: Configure step dependencies (run if previous succeeded/failed)
   ├─ Timeout: Max execution time (default 90 seconds per action)
   ├─ Retry policy: Retry on failure (exponential backoff)
   ├─ Scope + error handling: Catch errors, send notification
   └─ Terminate: Fail playbook gracefully (with message)
```

### 20.3 Playbook Examples

**Real-World Playbooks:**

**Example 1: Block Malicious IP (Response)**

```
Playbook: "Block-IP-on-Azure-Firewall"

Trigger: Microsoft Sentinel Incident

Actions:
1. Get incident
   └─ Output: Incident details (entities, severity, etc.)

2. Get entities (IP addresses)
   └─ Output: List of IPs involved in incident

3. For each IP:
   
   3a. Condition: Is IP external? (not internal network)
      └─ If YES: Continue
      └─ If NO: Skip (don't block internal IPs)
   
   3b. Azure Firewall - Add IP to deny list
      ├─ Input: IP address, rule name, priority
      └─ Output: Success/failure
   
   3c. Add comment to incident
      └─ Text: "IP {IP} blocked on Azure Firewall at {timestamp}"
   
   3d. Add tag to incident
      └─ Tag: "IP-Blocked"

4. Send email to SOC
   ├─ To: soc-team@contoso.com
   ├─ Subject: "Malicious IP blocked - Incident #{IncidentNumber}"
   └─ Body: "IP {IP} blocked on Azure Firewall. Incident: {IncidentTitle}"

5. Update incident
   ├─ Add comment: "Playbook 'Block-IP-on-Azure-Firewall' completed successfully"
   └─ Change status: Active (keep open for investigation)

Execution Time: ~30 seconds
Cost: ~$0.0001 per execution (4 actions × $0.000025)
```

**Example 2: Disable Compromised Account (Response)**

```
Playbook: "Disable-Compromised-User"

Trigger: Microsoft Sentinel Incident

Actions:
1. Get incident
2. Get entities (Accounts)

3. For each Account:
   
   3a. Get user details (Entra ID)
      └─ Output: User properties (UPN, department, manager)
   
   3b. Condition: Is user account (not service account)?
      └─ If NO: Skip (don't disable service accounts)
   
   3c. Disable user account (Entra ID)
      └─ Set: accountEnabled = false
   
   3d. Revoke refresh tokens (sign out all sessions)
      └─ Entra ID: Revoke sign-in sessions
   
   3e. Reset password (force change)
      └─ Entra ID: Require password change at next logon
   
   3f. Add comment to incident
      └─ Text: "User {UPN} disabled, sessions revoked, password reset"

4. Send email to user's manager
   ├─ To: {Manager email}
   ├─ Subject: "Security Alert: {User} account disabled"
   └─ Body: "User account disabled due to suspicious activity. Incident #{IncidentNumber}"

5. Send email to user
   ├─ To: {User email}
   ├─ Subject: "Your account has been disabled"
   └─ Body: "Contact IT security immediately. Incident #{IncidentNumber}"

6. Create ServiceNow ticket
   ├─ Short description: "Compromised account - {User}"
   ├─ Category: Security Incident
   ├─ Priority: High
   └─ Assigned to: security-team

7. Update incident
   └─ Add comment: "Playbook 'Disable-Compromised-User' completed"

Execution Time: ~1 minute
Cost: ~$0.0002 per execution (8 actions)
```

**Example 3: Isolate Infected Device (Response)**

```
Playbook: "Isolate-Device-MDE"

Trigger: Microsoft Sentinel Incident

Actions:
1. Get incident
2. Get entities (Hosts)

3. For each Host:
   
   3a. Microsoft Defender for Endpoint - Get machine details
      └─ Input: Device name or ID
      └─ Output: MDE machine object
   
   3b. Condition: Is device managed by MDE?
      └─ If NO: Skip (cannot isolate unmanaged)
   
   3c. MDE - Isolate device
      ├─ Isolation type: Full (no network access except MDE)
      ├─ Comment: "Isolated due to Sentinel incident #{IncidentNumber}"
      └─ Output: Isolation request ID
   
   3d. Add comment to incident
      └─ Text: "Device {DeviceName} isolated via MDE at {timestamp}"
   
   3e. Add tag to incident
      └─ Tag: "Device-Isolated"

4. Send Teams message to SOC
   ├─ Channel: SOC-Operations
   ├─ Title: "Device Isolated - Urgent"
   └─ Message: "Device {DeviceName} isolated due to incident #{IncidentNumber}. Review immediately."

5. Update incident
   ├─ Change severity: High → Critical (device isolated, urgent investigation)
   └─ Add comment: "Device isolation completed, escalated to Critical"

6. Create task for analyst
   ├─ Title: "Investigate isolated device {DeviceName}"
   ├─ Description: "Device isolated by playbook. Perform forensic analysis."
   └─ Assigned to: forensics-team@contoso.com

Execution Time: ~45 seconds
Cost: ~$0.00015 per execution (6 actions)
```

**Example 4: Enrich Incident with Threat Intelligence**

```
Playbook: "Enrich-IP-ThreatIntel"

Trigger: Microsoft Sentinel Incident

Actions:
1. Get incident
2. Get entities (IP addresses)

3. For each IP:
   
   3a. VirusTotal - Get IP report
      ├─ Input: IP address
      └─ Output: Reputation score, malicious detections, ASN, country
   
   3b. Compose enrichment data (JSON)
      └─ JSON: {
           "IP": "{IP}",
           "VT_Score": "{VT malicious count}/{VT total scans}",
           "ASN": "{ASN}",
           "Country": "{Country}",
           "FirstSeen": "{VT first seen}",
           "LastSeen": "{VT last seen}"
         }
   
   3c. Add comment to incident
      └─ Text: "IP Threat Intel:
                IP: {IP}
                VirusTotal: {VT_Score} malicious detections
                ASN: {ASN}
                Country: {Country}
                Reputation: {VT community score}"
   
   3d. Condition: Is IP malicious? (VT score > 3)
      └─ If YES:
         ├─ Change severity: Increase by 1 level
         ├─ Add tag: "Malicious-IP-Confirmed"
         └─ Trigger response playbook: "Block-IP-on-Azure-Firewall"
      └─ If NO:
         └─ Add tag: "IP-Checked-Clean"

4. Update incident
   └─ Add comment: "Threat intelligence enrichment completed"

Execution Time: ~20 seconds per IP
Cost: ~$0.0001 per IP (4 actions)
```

**Example 5: Notify SOC Team (Communication)**

```
Playbook: "Notify-SOC-Critical-Incident"

Trigger: Microsoft Sentinel Incident (via Automation Rule for Critical severity)

Actions:
1. Get incident

2. Compose incident summary (HTML)
   └─ HTML: 
      <h2>🚨 Critical Security Incident</h2>
      <p><b>Incident:</b> #{IncidentNumber} - {IncidentTitle}</p>
      <p><b>Severity:</b> {Severity}</p>
      <p><b>Created:</b> {CreatedTime}</p>
      <p><b>Entities:</b> {Entity list}</p>
      <p><b>Description:</b> {Description}</p>
      <p><b>Action Required:</b> Investigate immediately</p>
      <p><b>Portal Link:</b> <a href="{IncidentURL}">Open in Sentinel</a></p>

3. Send email to SOC team
   ├─ To: soc-team@contoso.com
   ├─ CC: soc-manager@contoso.com
   ├─ Subject: "🚨 CRITICAL: {IncidentTitle} - Incident #{IncidentNumber}"
   ├─ Body: {HTML summary from step 2}
   └─ Importance: High

4. Post to Microsoft Teams (SOC channel)
   ├─ Channel: SOC-Critical-Alerts
   ├─ Message: @mention SOC team
   └─ Adaptive Card: 
      ├─ Title: "Critical Incident #{IncidentNumber}"
      ├─ Summary: {IncidentTitle}
      ├─ Actions: 
      │  ├─ Button: "View in Sentinel" (link to incident)
      │  └─ Button: "Acknowledge" (update incident with response)

5. Condition: Is after hours (6 PM - 8 AM) or weekend?
   └─ If YES:
      ├─ Send SMS to on-call analyst (Twilio)
      │  └─ Text: "🚨 CRITICAL incident #{IncidentNumber}: {IncidentTitle}. Check Teams/Email."
      └─ Call PagerDuty API (escalate)

6. Update incident
   └─ Add comment: "SOC team notified (email, Teams, SMS)"

Execution Time: ~15 seconds
Cost: ~$0.00015 per execution (6 actions) + SMS cost (~$0.0075)
```

### 20.4 Playbook Permissions

**Granting Playbook Access to Resources:**

```
Playbook Authentication Methods:

1️⃣ Managed Identity (Recommended)
   ├─ What: Playbook authenticates as Sentinel (no credentials)
   ├─ How: Enable managed identity on Logic App
   ├─ Permissions: Grant RBAC roles to managed identity
   ├─ Benefits: Secure (no credentials stored), easy management
   └─ Use: Sentinel actions, Azure resources (Entra ID, MDE, etc.)

   Configuration:
   Step 1: Enable managed identity
   ├─ Logic App → Identity → System assigned: On
   └─ Note: Managed identity ID (object ID)

   Step 2: Grant permissions (RBAC)
   ├─ Sentinel → Settings → Workspace settings → Access control (IAM)
   ├─ Add role assignment:
   │  ├─ Role: Microsoft Sentinel Responder (manage incidents)
   │  ├─ Assign to: Logic App (managed identity)
   │  └─ Save
   │
   ├─ Entra ID → Roles and administrators → Grant roles:
   │  ├─ Security Administrator (disable users, reset passwords)
   │  ├─ User Administrator (manage users)
   │  └─ Or custom role (least privilege)
   │
   └─ MDE → Settings → Permissions → Grant:
      ├─ Machine.Isolate (isolate devices)
      ├─ Machine.Scan (run antivirus)
      └─ Or API permissions (least privilege)

2️⃣ OAuth (User-Based)
   ├─ What: User grants permissions to playbook
   ├─ How: Sign in to connector (Teams, Outlook, etc.)
   ├─ Permissions: Based on user's permissions
   ├─ Drawback: Tied to specific user (if user leaves, playbook breaks)
   └─ Use: Teams, Outlook, Slack (user-based connectors)

   Configuration:
   ├─ Logic App → Connections → Add connection
   ├─ Select connector (e.g., Microsoft Teams)
   ├─ Sign in: User authenticates
   └─ Grant: User grants permissions to playbook

3️⃣ API Key (Third-Party)
   ├─ What: Service API key (VirusTotal, AlienVault, etc.)
   ├─ How: Store API key in Key Vault (secure)
   ├─ Permissions: Based on API key scope
   └─ Use: Third-party services (VirusTotal, threat intel platforms)

   Configuration:
   ├─ Get API key: From service (VirusTotal account)
   ├─ Store: Azure Key Vault (secure storage)
   ├─ Logic App → Connections → HTTP action
   └─ Headers: Add API key header (X-ApiKey: {key from Key Vault})

Least Privilege Principle:
✅ Grant minimum necessary permissions
✅ Sentinel Responder: Manage incidents (not Contributor - too broad)
✅ Security Administrator: Disable users (not Global Admin)
✅ MDE isolate: Specific actions (not all MDE permissions)

Common Permission Issues:
❌ Playbook fails with "Forbidden" error
   → Solution: Grant managed identity appropriate RBAC role

❌ Playbook cannot update incident
   → Solution: Grant "Microsoft Sentinel Responder" role

❌ Playbook cannot disable user
   → Solution: Grant "User Administrator" or "Security Administrator" role

❌ Connection expires (OAuth)
   → Solution: Use managed identity (doesn't expire) or refresh connection
```

**🎯 Exam Tip:**
- **Playbooks**: Logic Apps workflows, automate complex response actions
- **Trigger**: Incident (via automation rule), alert, manual, scheduled, HTTP webhook
- **Actions**: Sentinel (update incident), Entra ID (disable user), MDE (isolate device), communication (email, Teams), ITSM (ServiceNow), threat intel (VirusTotal), network (block IP), control flow (if/else, loops)
- **Common scenarios**: Enrichment (TI lookup), response (block IP, disable user, isolate device), notification (email, Teams, SMS), investigation (collect logs)
- **Authentication**: Managed identity (recommended), OAuth (user-based), API key (third-party)
- **Permissions**: RBAC roles (Sentinel Responder, Security Administrator, MDE isolate)
- **Cost**: ~$0.000025 per action (typical playbook: $0.0001-$0.001 per execution)
- **Exam scenario**: "Automate device isolation" → Use playbook (not automation rule)

---

## 21. SOAR Integration

### 21.1 SOAR Overview

**Security Orchestration, Automation, and Response:**

```
SOAR Definition:
- Security Orchestration: Coordinate multiple security tools
- Automation: Execute actions without human intervention
- Response: Remediate threats automatically

Microsoft Sentinel SOAR Capabilities:
├─ Orchestration: Integrate 1,000+ services (Logic Apps connectors)
├─ Automation: Automation rules + Playbooks
├─ Response: Block IP, disable user, isolate device, etc.
└─ Intelligence: Threat intelligence, enrichment, UEBA

SOAR Benefits:

1️⃣ Speed (Time Savings)
   ├─ Manual response: 30-60 minutes (analyst investigation + action)
   ├─ Automated response: 1-2 minutes (playbook execution)
   └─ Improvement: 95%+ reduction in MTTR

2️⃣ Consistency (No Human Error)
   ├─ Manual: Steps may be skipped, errors possible
   ├─ Automated: Same steps every time (checklist executed)
   └─ Improvement: 100% compliance with runbooks

3️⃣ Scalability (Handle More Incidents)
   ├─ Manual: 1 analyst = 20-30 incidents/day
   ├─ Automated: Playbooks = 1,000+ incidents/day (no human limit)
   └─ Improvement: 50x increase in throughput

4️⃣ Cost Efficiency
   ├─ Manual: $50-100 per incident (analyst time)
   ├─ Automated: $0.0001-0.001 per incident (playbook execution)
   └─ Improvement: 99%+ cost reduction (for automatable incidents)

5️⃣ Reduced Alert Fatigue
   ├─ Manual: Analysts overwhelmed (10,000 alerts/day)
   ├─ Automated: Low-priority alerts auto-resolved (7,000 automated)
   └─ Improvement: Analysts focus on high-value threats (3,000 remaining)
```

### 21.2 Common SOAR Integrations

**Key Integration Categories:**

```
1️⃣ ITSM (IT Service Management)
   ├─ ServiceNow: Create incident, update ticket, close ticket
   ├─ Jira: Create issue, add comment, change status
   ├─ Zendesk: Create ticket, assign to agent
   └─ Remedy: Create incident, escalate

   Use Cases:
   ✅ Auto-create tickets for all Sentinel incidents
   ✅ Bi-directional sync (Sentinel ↔ ServiceNow)
   ✅ Ticketing workflow (assignment, escalation, closure)

2️⃣ Communication & Collaboration
   ├─ Microsoft Teams: Post to channel, send adaptive card, @mention
   ├─ Slack: Post message, create channel, send direct message
   ├─ Email: Send notification, include incident details
   ├─ SMS: Twilio, Plivo (urgent alerts)
   └─ Voice: Twilio (call on-call analyst)

   Use Cases:
   ✅ Notify SOC team (Teams, Slack)
   ✅ Escalate to on-call (SMS, voice call)
   ✅ Manager notifications (email)

3️⃣ Threat Intelligence
   ├─ VirusTotal: Query file hash, IP, domain, URL
   ├─ AlienVault OTX: Query threat intel, get pulse data
   ├─ ThreatConnect: Query indicators, add IOCs
   ├─ MISP: Query threat sharing platform, export indicators
   └─ Recorded Future: Get threat intelligence, risk scores

   Use Cases:
   ✅ Enrich incidents (IP reputation, file hash lookups)
   ✅ Validate threats (check if IP/domain malicious)
   ✅ Share intelligence (export IOCs to TI platforms)

4️⃣ Identity & Access Management
   ├─ Entra ID (Azure AD): Disable user, reset password, revoke sessions
   ├─ Active Directory: Disable account, add to group, remove from group
   ├─ Okta: Deactivate user, clear sessions
   └─ Ping Identity: Revoke access tokens

   Use Cases:
   ✅ Disable compromised accounts (automatic)
   ✅ Force password reset (security policy)
   ✅ Quarantine user (add to restricted group)

5️⃣ Endpoint Security (EDR/XDR)
   ├─ Microsoft Defender for Endpoint: Isolate device, run AV scan, collect forensics
   ├─ CrowdStrike: Contain host, get device details
   ├─ Carbon Black: Isolate endpoint, ban hash
   ├─ SentinelOne: Quarantine device, remediate threat
   └─ Cortex XDR: Isolate endpoint, block file

   Use Cases:
   ✅ Isolate infected devices (automatic containment)
   ✅ Run antivirus scans (on-demand)
   ✅ Collect forensic data (investigation package)

6️⃣ Network Security (Firewall, Proxy)
   ├─ Palo Alto Networks: Block IP, create address object, update policy
   ├─ Fortinet FortiGate: Block IP, add firewall rule
   ├─ Cisco ASA: Add to ACL, block IP
   ├─ Azure Firewall: Add IP to deny list
   ├─ Zscaler: Block URL, add to blocklist
   └─ Cisco Umbrella: Block domain (DNS security)

   Use Cases:
   ✅ Block malicious IPs (automatic firewall update)
   ✅ Block C2 domains (DNS-level blocking)
   ✅ Update firewall rules (policy automation)

7️⃣ Cloud Security
   ├─ AWS: Revoke IAM credentials, block security group, snapshot instance
   ├─ Azure: Disable VM, revoke managed identity, update NSG
   ├─ GCP: Suspend service account, update firewall rule
   └─ Microsoft Defender for Cloud Apps: Block cloud app, revoke OAuth

   Use Cases:
   ✅ Respond to cloud threats (isolate compromised VM)
   ✅ Revoke access (compromised credentials)
   ✅ Update cloud security policies (NSG, security groups)

8️⃣ Email Security
   ├─ Microsoft Defender for Office 365: Delete email, quarantine, report phishing
   ├─ Exchange Online: Delete mailbox items, block sender
   ├─ Proofpoint: Quarantine email, block sender
   └─ Mimecast: Hold/release email, block sender

   Use Cases:
   ✅ Remove phishing emails (from all mailboxes)
   ✅ Block sender (prevent future emails)
   ✅ Quarantine suspicious attachments (automatic)

9️⃣ SIEM & Log Management
   ├─ Splunk: Run search, get events, create alert
   ├─ QRadar: Query offense, get flows
   ├─ ArcSight: Query correlation logs
   └─ Elasticsearch: Query logs, get events

   Use Cases:
   ✅ Cross-SIEM correlation (Sentinel + Splunk)
   ✅ Enrich with external logs (legacy SIEM)
   ✅ Migration scenarios (Splunk → Sentinel)

🔟 Custom Integrations (HTTP)
   ├─ REST API: Call any service with API
   ├─ Webhooks: Receive events from external systems
   ├─ Custom Logic: PowerShell, Python (Azure Functions)
   └─ Legacy systems: SOAP, FTP, database queries

   Use Cases:
   ✅ Integrate proprietary tools (custom APIs)
   ✅ Legacy system integration (no built-in connector)
   ✅ Complex logic (Azure Functions + Logic Apps)
```

### 21.3 SOAR Workflow Examples

**End-to-End SOAR Scenarios:**

**Scenario 1: Phishing Response (Full Automation)**

```
Incident: "Phishing email detected - 50 users received"

Workflow:
1. Alert fires (MDO detects phishing)
2. Sentinel creates incident
3. Automation rule triggers playbook: "Phishing-Response"

Playbook Steps:
├─ 1. Get incident details
├─ 2. Get entities (email message ID, sender, recipients)
├─ 3. For each recipient:
│  ├─ 3a. Delete email from mailbox (MDO API)
│  ├─ 3b. Notify recipient (email: "Phishing email removed")
│  └─ 3c. Add comment: "Email removed from {recipient} mailbox"
│
├─ 4. Block sender (Exchange Online)
│  └─ Add sender to blocked senders list
│
├─ 5. Check sender IP (VirusTotal)
│  └─ If malicious: Block IP on firewall
│
├─ 6. Create ServiceNow ticket
│  ├─ Title: "Phishing campaign - {sender}"
│  ├─ Description: "50 users targeted, emails removed automatically"
│  └─ Priority: Medium
│
├─ 7. Post to Teams (SOC channel)
│  └─ Message: "Phishing campaign detected and mitigated. Ticket: {ServiceNow #}"
│
└─ 8. Close incident
   └─ Classification: True Positive - Security Testing (if internal test)
          or True Positive - Malicious Activity (if real phishing)

Result: Phishing campaign mitigated in <5 minutes (no analyst intervention)
Manual time: 2-3 hours (analyst time to remove emails, notify users, create ticket)
Time saved: 95%+
```

**Scenario 2: Compromised Account Response**

```
Incident: "Impossible travel - User signed in from US and China in 1 hour"

Workflow:
1. Analytics rule fires (impossible travel detection)
2. Sentinel creates incident (High severity)
3. Automation rule triggers playbook: "Compromised-Account-Response"

Playbook Steps:
├─ 1. Get incident details
├─ 2. Get entities (user account)
├─ 3. Get user details (Entra ID)
│  └─ Output: User UPN, department, manager email, risk score
│
├─ 4. Check UEBA risk score
│  ├─ If risk score > 70: High risk (likely compromised)
│  └─ If risk score < 70: Medium risk (investigate)
│
├─ 5. Condition: If high risk OR severity = Critical
│  └─ Then:
│     ├─ 5a. Disable user account (Entra ID)
│     ├─ 5b. Revoke refresh tokens (sign out all sessions)
│     ├─ 5c. Reset password (force change at next logon)
│     ├─ 5d. Add user to "Quarantine" group (restrict access)
│     └─ 5e. Add comment: "Account disabled - high risk compromise"
│
├─ 6. Send email to user's manager
│  ├─ To: {Manager email}
│  ├─ Subject: "Security Alert: {User} account disabled"
│  └─ Body: "Account disabled due to suspicious activity. Contact IT Security."
│
├─ 7. Send email to user (personal email if available)
│  └─ Message: "Your work account disabled. Contact IT Security immediately."
│
├─ 8. Create high-priority ServiceNow ticket
│  ├─ Title: "Compromised account - {User}"
│  ├─ Assigned to: security-response-team
│  └─ Priority: High
│
├─ 9. Run advanced hunting (Defender XDR)
│  └─ Query: Get all user activities (past 7 days)
│  └─ Output: Sign-ins, file access, email sent, devices used
│
├─ 10. Post to Teams (SOC channel)
│  └─ Adaptive card:
│     ├─ Title: "Compromised Account - {User}"
│     ├─ Details: Incident #, risk score, actions taken
│     └─ Button: "View in Sentinel" (link)
│
└─ 11. Update incident
   ├─ Add comment: "Automated response completed (account disabled)"
   └─ Change status: Active (keep open for investigation)

Result: Account disabled in <2 minutes (automatic containment)
Manual time: 15-20 minutes (analyst time to disable, notify, create ticket)
Time saved: 90%+
```

**Scenario 3: Malware Outbreak Response**

```
Incident: "Malware detected on 10 devices"

Workflow:
1. MDE detects malware (multiple devices)
2. Sentinel creates incident (Critical severity)
3. Automation rule triggers playbook: "Malware-Outbreak-Response"

Playbook Steps:
├─ 1. Get incident details
├─ 2. Get entities (hosts, file hashes, users)
├─ 3. For each infected host:
│  ├─ 3a. Isolate device (MDE)
│  │  └─ Full isolation (no network access except MDE)
│  │
│  ├─ 3b. Run antivirus scan (MDE)
│  │  └─ Full scan (all drives)
│  │
│  ├─ 3c. Collect investigation package (MDE)
│  │  └─ Memory dump, process list, network connections, registry
│  │
│  └─ 3d. Add comment: "Device {DeviceName} isolated and scanned"
│
├─ 4. For each file hash (malware):
│  ├─ 4a. Query VirusTotal
│  │  └─ Get malware details, family name, behavior
│  │
│  ├─ 4b. Block hash globally (MDE)
│  │  └─ Add to global block list (all devices)
│  │
│  └─ 4c. Add comment: "Hash {FileHash} blocked globally"
│
├─ 5. For each user (whose device infected):
│  ├─ 5a. Force password reset (Entra ID)
│  │  └─ Require password change at next logon
│  │
│  ├─ 5b. Revoke sessions (sign out)
│  │
│  └─ 5c. Send email: "Your device was infected. Password reset required."
│
├─ 6. Update firewall (block C2 IP)
│  └─ If malware has C2: Block C2 IP on Azure Firewall
│
├─ 7. Create major incident (ServiceNow)
│  ├─ Severity: SEV-1 (major incident)
│  ├─ Title: "Malware outbreak - {MalwareName} - 10 devices"
│  ├─ Assigned to: incident-response-team
│  └─ Priority: Critical
│
├─ 8. Notify executive team
│  ├─ Send email to CISO, CIO, security managers
│  ├─ Subject: "🚨 CRITICAL: Malware outbreak detected - 10 devices isolated"
│  └─ Body: Incident details, actions taken, next steps
│
├─ 9. Post to Teams (multiple channels)
│  ├─ SOC channel: Full details (technical)
│  ├─ Security leadership: Executive summary
│  └─ IT operations: Impact (devices offline)
│
└─ 10. Update incident
   ├─ Add comment: "Automated response: 10 devices isolated, malware blocked, users notified"
   ├─ Change severity: Critical (confirmed outbreak)
   └─ Assign to: incident-response-team@contoso.com

Result: Outbreak contained in <5 minutes (all devices isolated)
Manual time: 1-2 hours (analyst time to isolate each device, block malware, notify users)
Time saved: 95%+
```

### 21.4 SOAR Metrics & Measurement

**Measuring SOAR Effectiveness:**

```
Key SOAR Metrics:

1️⃣ MTTR (Mean Time to Respond)
   ├─ Definition: Time from alert to remediation
   ├─ Calculation: Sum of (resolve time - alert time) / # incidents
   ├─ Target: 
   │  ├─ Critical: <1 hour (automated), <4 hours (manual)
   │  ├─ High: <4 hours (automated), <24 hours (manual)
   │  └─ Medium: <24 hours (automated), <72 hours (manual)
   ├─ Improvement: 80-95% reduction with SOAR
   └─ Tracking: Sentinel incident metrics, ServiceNow reports

2️⃣ Automation Rate
   ├─ Definition: % of incidents auto-resolved (no analyst intervention)
   ├─ Calculation: (Automated incidents / Total incidents) × 100%
   ├─ Target: 40-60% (realistic), 80%+ (mature SOAR)
   ├─ Breakdown:
   │  ├─ Fully automated: 30-50% (auto-closed, no human action)
   │  ├─ Semi-automated: 20-30% (playbook assists, analyst closes)
   │  └─ Manual: 20-40% (complex, requires human judgment)
   └─ Tracking: Automation rule execution logs, playbook run history

3️⃣ Playbook Success Rate
   ├─ Definition: % of playbook executions that succeed (vs fail)
   ├─ Calculation: (Successful runs / Total runs) × 100%
   ├─ Target: >95% (high reliability)
   ├─ Failures:
   │  ├─ Permission errors: Managed identity missing roles
   │  ├─ Timeout errors: API calls taking too long
   │  ├─ Logic errors: Incorrect conditions, missing data
   │  └─ External API errors: Third-party service down
   └─ Tracking: Logic Apps run history, error logs

4️⃣ Time Savings (Efficiency Gain)
   ├─ Definition: Analyst hours saved due to automation
   ├─ Calculation: 
   │  └─ (Manual time per incident × # automated incidents) - Playbook cost
   ├─ Example:
   │  ├─ Manual: 30 min/incident × 5,000 incidents/month = 2,500 hours
   │  ├─ Automated: 2 min/incident × 5,000 = 167 hours
   │  └─ Savings: 2,333 hours/month (93% reduction)
   └─ Cost savings: 2,333 hours × $50/hour = $116,650/month

5️⃣ False Positive Reduction
   ├─ Definition: % reduction in false positives (via automation)
   ├─ Calculation: (FP reduction / Original FPs) × 100%
   ├─ Example:
   │  ├─ Before: 10,000 alerts/day, 70% FP = 7,000 FP/day
   │  ├─ After: 3,000 alerts/day (7,000 auto-closed) = 0 FP/day from those
   │  └─ Reduction: 7,000/10,000 = 70% reduction
   └─ Benefit: Analysts focus on real threats (not noise)

6️⃣ Incident Volume Handled
   ├─ Definition: # incidents handled per analyst (with SOAR)
   ├─ Calculation: Total incidents / # analysts
   ├─ Benchmark:
   │  ├─ Manual: 20-30 incidents/analyst/day
   │  ├─ With SOAR: 50-100 incidents/analyst/day (2-3x increase)
   │  └─ Fully automated: Unlimited (playbooks scale infinitely)
   └─ Business impact: Scale SOC without hiring more analysts

Dashboard Metrics:
✅ MTTR trend (weekly, monthly)
✅ Automation rate (by severity, by rule)
✅ Playbook execution count (top 10 playbooks)
✅ Playbook success rate (by playbook)
✅ Time saved (hours/month, cost savings)
✅ Incident volume (total, automated, manual)
✅ Analyst productivity (incidents/analyst/day)

ROI Calculation:
Cost of SOAR:
├─ Logic Apps: ~$100-500/month (depends on executions)
├─ Third-party connectors: ~$500-2,000/month (VirusTotal, etc.)
├─ Development time: 40-80 hours initial setup (one-time)
└─ Maintenance: 10-20 hours/month (ongoing)

Benefits:
├─ Analyst time saved: $100,000-500,000/month (depends on scale)
├─ Faster MTTR: Reduced breach cost (minutes vs hours)
├─ Higher SOC capacity: 2-3x more incidents handled
└─ Better security: Consistent response (no human error)

ROI: 10-50x return on investment (typical for mature SOAR programs)
```

**🎯 Exam Tip:**
- **SOAR**: Security Orchestration, Automation, Response (coordinate tools, automate actions, remediate threats)
- **Benefits**: Speed (95% MTTR reduction), consistency (no human error), scalability (50x throughput), cost efficiency (99% cost reduction for automatable incidents)
- **Key integrations**: ITSM (ServiceNow, Jira), communication (Teams, Slack, email), threat intel (VirusTotal, AlienVault), IAM (Entra ID, Okta), EDR (MDE, CrowdStrike), network (Palo Alto, Azure Firewall), email (MDO, Exchange), cloud (AWS, Azure, GCP)
- **Common workflows**: Phishing response (remove emails, block sender, notify users), compromised account (disable, revoke sessions, reset password), malware outbreak (isolate devices, block hash, notify users)
- **Metrics**: MTTR (time to respond), automation rate (% auto-resolved), playbook success rate (>95%), time savings (analyst hours saved), false positive reduction
- **ROI**: 10-50x return on investment (typical mature SOAR)
- **Exam scenario**: "Integrate with ServiceNow" → Use playbook with ServiceNow connector

---

**🎉 END OF MODULE 5 PART 4! 🎉**

You've mastered **Incident Management & SOAR**:
- ✅ **Section 16**: Incident Management (lifecycle, properties, triage process, workspace management)
- ✅ **Section 17**: Incident Investigation (systematic approach, KQL investigation queries, entity investigation, evidence collection)
- ✅ **Section 18**: Investigation Graph & Timeline (visual attack chains, chronological events, combined workflows)
- ✅ **Section 19**: Automation Rules (incident-triggered workflows, conditions, actions, real-world examples, best practices)
- ✅ **Section 20**: Playbooks (Logic Apps workflows, triggers, actions, authentication, real-world examples)
- ✅ **Section 21**: SOAR Integration (orchestration, common integrations, end-to-end workflows, metrics, ROI)

**Progress: Module 5 Part 4 COMPLETE! (~18,000 words)**

---

## 📊 **Module 5 Overall Progress Update:**

**Completed Parts (1-4):**
- **Part 1**: Foundation & Configuration (~15,000 words) ✅
- **Part 2**: Data Collection & Optimization (~15,000 words) ✅
- **Part 3**: Analytics Rules & Detection (~20,000 words) ✅
- **Part 4**: Incidents & Automation (~18,000 words) ✅

**Total So Far: ~68,000 words | 21 sections complete**

**Module 5 Progress: 75% Complete!** 🎉

---

**Remaining Parts (5-6) - Just 25% left!**

**Part 5** - Threat Hunting & Visualization (~12,000 words):
- Hunting Queries (built-in + custom, MITRE ATT&CK mapping)
- Bookmarks & Livestream (save findings, real-time monitoring)
- Notebooks (Jupyter, Python, ML for advanced analysis)
- Workbooks (dashboards, reporting, compliance)
- UEBA (User Entity Behavior Analytics, risk scoring)

**Part 6** - Exam Mastery (~8,000 words):
- 20+ comprehensive practice questions (scenario-based)
- KQL deep dive (exam-focused queries, common patterns)
- Exam strategies (time management, question types)
- Final review checklist (all critical topics)

**Continue to Part 5 (Threat Hunting & Visualization)?** This is where proactive defense happens! 🔍🎯