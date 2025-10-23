# SC-200 Study Notes - Module 5: Microsoft Sentinel (Part 3)
## 🎯 Analytics Rules & Detection Engineering

**Continuation of Parts 1 & 2** - Sections 9-12
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide + Latest Sentinel Updates

---

## 📚 Table of Contents - Part 3

9. [Analytics Rules Overview](#9-analytics-rules-overview)
10. [Scheduled Query Rules](#10-scheduled-query-rules)
11. [Near-Real-Time (NRT) Rules](#11-near-real-time-nrt-rules)
12. [Advanced Rule Types](#12-advanced-rule-types)
13. [Entity Mapping](#13-entity-mapping)
14. [ASIM Parsers](#14-asim-parsers)
15. [Rule Tuning & Optimization](#15-rule-tuning--optimization)

---

## 9. Analytics Rules Overview

### 9.1 What are Analytics Rules?

**Definition & Purpose:**

```
Analytics Rule = Detection logic that generates alerts when threats are detected

Purpose:
├─ Detect: Identify suspicious activities, threats, policy violations
├─ Alert: Generate alerts when conditions met
├─ Incident: Group related alerts into incidents
├─ Automate: Trigger playbooks for response
└─ Investigate: Provide context (entities, timeline, evidence)

Analytics Rule Lifecycle:
┌─────────────────────────────────────────────────────────┐
│ 1. Data Ingestion → Logs stored in workspace            │
│ 2. Rule Execution → KQL query runs on schedule          │
│ 3. Detection → Query returns results (match found)      │
│ 4. Alert Creation → Alert generated with details        │
│ 5. Incident Creation → Alert(s) grouped into incident   │
│ 6. Automation → Playbooks triggered (optional)          │
│ 7. Investigation → Analyst triages and responds         │
└─────────────────────────────────────────────────────────┘
```

### 9.2 Rule Types Comparison

**5 Types of Analytics Rules:**

```
┌───────────────────────────────────────────────────────────────────────┐
│ Rule Type         | Detection Method | Latency | Complexity | Use Case│
├───────────────────────────────────────────────────────────────────────┤
│ 1. Scheduled      | KQL query        | 5 min - | High      | Custom  │
│    Query          | (user-defined)   | 14 days | (flexible)| threats │
│                   |                  |         |           |         │
│ 2. Near-Real-Time | KQL query        | 1-10    | Medium    | Time-   │
│    (NRT)          | (simplified)     | minutes | (limited) | critical│
│                   |                  |         |           |         │
│ 3. Anomaly        | Machine Learning | Minutes | Low       | Unknown │
│    Detection      | (pre-built)      | to hours| (template)| threats │
│                   |                  |         |           |         │
│ 4. Fusion        | ML Correlation   | Real-   | None      | Multi-  │
│                   | (Microsoft-built)| time    | (auto)    | stage   │
│                   |                  |         |           | attacks │
│                   |                  |         |           |         │
│ 5. Microsoft     | Import alerts    | Real-   | None      | Unify   │
│    Security      | (external SIEM)  | time    | (auto)    | alerts  │
└───────────────────────────────────────────────────────────────────────┘

Decision Tree: Which Rule Type?

Do you know the detection pattern?
├─ YES: Scheduled or NRT rule
│  └─ Is sub-minute detection critical?
│     ├─ YES: NRT rule (1-min execution)
│     └─ NO: Scheduled rule (flexible, powerful)
│
└─ NO: Anomaly or Fusion rule
   └─ Is it a multi-stage attack?
      ├─ YES: Fusion rule (correlates multiple signals)
      └─ NO: Anomaly rule (ML baseline, detect deviations)

Import alerts from Defender XDR/Defender for Cloud?
└─ Use Microsoft Security rule (bidirectional sync)
```

### 9.3 Rule Components (Common to All Types)

**Essential Rule Elements:**

```
Every Analytics Rule Has:

1️⃣ General Settings
   ├─ Name: Rule identifier (descriptive, unique)
   ├─ Description: What the rule detects, why it matters
   ├─ Severity: Informational, Low, Medium, High, Critical
   ├─ Tactics: MITRE ATT&CK tactics (Initial Access, Execution, etc.)
   ├─ Techniques: MITRE ATT&CK techniques (T1078, T1059, etc.)
   ├─ Status: Enabled or Disabled
   └─ Alert generation: Create alert when query returns results

2️⃣ Rule Logic (Type-Specific)
   ├─ Scheduled: KQL query + schedule (run frequency)
   ├─ NRT: Simplified KQL query (1-min execution)
   ├─ Anomaly: ML template + threshold (confidence score)
   ├─ Fusion: Enabled/disabled (no configuration)
   └─ Microsoft Security: Source products (MDE, MDO, MDC, etc.)

3️⃣ Entity Mapping (Optional but Recommended)
   ├─ Purpose: Link alerts to entities (users, IPs, hosts, files)
   ├─ Entities: Account, Host, IP, File, URL, Process, Mailbox, etc.
   ├─ Mapping: Map query results to entity fields
   └─ Benefit: Investigation graph, entity timeline, correlation

4️⃣ Alert Enrichment (Optional)
   ├─ Custom details: Add query results to alert (key findings)
   ├─ Alert details: Dynamic alert name/description (based on results)
   └─ Benefit: Faster triage (key info in alert, no query needed)

5️⃣ Incident Settings
   ├─ Create incidents: Group related alerts into incidents
   ├─ Grouping: Group alerts by entities, time window, or all alerts
   ├─ Re-open closed incidents: If new alert matches closed incident
   └─ Suppression: Stop creating alerts for X hours after first alert

6️⃣ Automation
   ├─ Automated response: Trigger playbooks when alert created
   ├─ Playbook selection: Choose playbook(s) to run
   └─ Benefit: Immediate response (block IP, disable user, etc.)

Rule Configuration Flow:
┌─────────────────────────────────────────────────────────┐
│ General → Rule Logic → Entity Mapping → Alert Details  │
│ → Incident Settings → Automation → Review + Create     │
└─────────────────────────────────────────────────────────┘
```

### 9.4 Rule Deployment Methods

**How to Create/Deploy Rules:**

```
Method 1: Azure Portal (Manual - Recommended for Learning)
─────────────────────────────────────────────────────────
Sentinel → Analytics → Create → Scheduled query rule

Pros: ✅ User-friendly, wizard-based, immediate testing
Cons: ❌ Manual (not scalable), single workspace

Method 2: Content Hub (Pre-built Solutions)
─────────────────────────────────────────────────────────
Sentinel → Content hub → Search for solution → Install

What's Included:
├─ Data connectors (prerequisites)
├─ Analytics rules (10-100+ rules per solution)
├─ Workbooks (dashboards)
├─ Hunting queries
├─ Playbooks (automation templates)
└─ Parser functions (if needed)

Example Solutions:
├─ Microsoft Entra ID (100+ rules for sign-in threats)
├─ Windows Security Events (50+ rules for host threats)
├─ AWS (CloudTrail threat detection)
├─ Palo Alto Networks (firewall threat detection)
└─ 500+ solutions available (Microsoft + partners)

Pros: ✅ Quick deployment, best practices, vendor-supported
Cons: ❌ May need tuning (too many alerts initially)

Method 3: ARM Templates (Infrastructure as Code)
─────────────────────────────────────────────────────────
Export rule as ARM template → Deploy via Azure CLI/PowerShell

Use Cases:
├─ Multi-workspace deployment (consistent rules)
├─ Version control (Git repository)
├─ CI/CD pipeline (automated deployment)
└─ Disaster recovery (rapid rebuild)

Example ARM Template:
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [{
    "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
    "kind": "Scheduled",
    "properties": {
      "displayName": "Brute Force Attack Detection",
      "severity": "High",
      "query": "SecurityEvent | where EventID == 4625 | ...",
      "queryFrequency": "PT5M",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 10
    }
  }]
}

Pros: ✅ Scalable, version-controlled, consistent
Cons: ❌ Requires DevOps knowledge, JSON editing

Method 4: API (Programmatic)
─────────────────────────────────────────────────────────
Use Azure REST API or Azure PowerShell/CLI

Use Case: Custom automation, integration with tools

Example (PowerShell):
New-AzSentinelAlertRule `
  -ResourceGroupName "rg-sentinel" `
  -WorkspaceName "sentinel-prod" `
  -Kind "Scheduled" `
  -DisplayName "Suspicious PowerShell" `
  -Query "SecurityEvent | where EventID == 4688 | ..." `
  -Frequency "PT5M"

Pros: ✅ Automation, integration, bulk operations
Cons: ❌ Requires scripting knowledge

Recommendation for SC-200 Exam:
- Understand: All methods (portal, Content hub, ARM, API)
- Practice: Portal (wizard) + Content hub (solutions)
- Know: When to use each method
```

**🎯 Exam Tip:**
- **5 rule types**: Scheduled (custom KQL), NRT (1-min), Anomaly (ML), Fusion (multi-stage), Microsoft Security (import)
- **Rule components**: General settings, rule logic, entity mapping, alert enrichment, incident settings, automation
- **Deployment**: Portal (manual), Content hub (pre-built solutions), ARM templates (IaC), API (programmatic)
- **Best practice**: Start with Content hub solutions (pre-built, vendor-supported), then customize
- **Severity levels**: Informational, Low, Medium, High, Critical (map to business impact)
- **MITRE ATT&CK**: Always map rules to tactics and techniques (exam questions focus on this)

---

## 10. Scheduled Query Rules

### 10.1 Scheduled Rule Basics

**Most Common Rule Type (70-80% of Custom Rules):**

```
Scheduled Query Rule:
- Runs: On schedule (every X minutes/hours/days)
- Logic: KQL query (unlimited complexity)
- Detection: Query returns results → Alert created
- Flexibility: Full KQL capabilities (joins, aggregations, functions)

Key Parameters:

1️⃣ Query Frequency (How often rule runs)
   ├─ Range: 5 minutes to 14 days
   ├─ Common: 5 min (real-time threats), 1 hour (normal), 24 hours (slow threats)
   └─ Recommendation: Balance latency vs performance (don't overload workspace)

2️⃣ Lookup Period (How far back to look)
   ├─ Range: 5 minutes to 14 days
   ├─ Common: Same as frequency (e.g., 5-min rule looks back 5 min)
   ├─ Exception: Baseline rules (look back 30 days to establish pattern)
   └─ Note: Lookup period ≥ Query frequency (avoid data gaps)

3️⃣ Alert Threshold
   ├─ When to alert: Number of results > threshold
   ├─ Example: Alert if query returns >10 results
   └─ Use: Reduce noise (ignore single occurrences)

4️⃣ Suppression
   ├─ Stop generating alerts: For X hours after first alert
   ├─ Use: Prevent alert fatigue (same issue, multiple alerts)
   └─ Example: Brute force detected, suppress for 24 hours

Example Configuration:
┌─────────────────────────────────────────────────────────┐
│ Rule: Brute Force Attack Detection                      │
│ Query frequency: 5 minutes (check every 5 min)         │
│ Lookup period: 5 minutes (analyze last 5 min of data)  │
│ Alert threshold: Greater than 10 (>10 failed logins)   │
│ Suppression: 24 hours (don't alert again for same user)│
└─────────────────────────────────────────────────────────┘
```

### 10.2 Writing Effective KQL Queries

**KQL Query Structure for Analytics Rules:**

```kql
// Standard Pattern for Analytics Rules:

TableName
| where TimeGenerated > ago(QueryPeriod)  // Time filter (automatic)
| where <FilterCondition>  // Primary filter (narrow data)
| where <ThreatIndicator>  // Threat-specific logic
| summarize <Aggregation> by <GroupBy>, bin(TimeGenerated, TimeWindow)
| where <Threshold>  // Alert threshold
| project <OutputFields>  // Select relevant fields
| extend <Enrichment>  // Add context (optional)

Key Principles:

1️⃣ Filter Early (Performance)
   - Use where clauses at the top (reduce dataset size)
   - Don't: Load entire table then filter
   - Do: Filter immediately after table name

2️⃣ Use Aggregation (Detect Patterns)
   - Count, sum, avg, dcount (distinct count)
   - Group by: User, IP, Host, Time window
   - Example: Count failed logins per user per 5 min

3️⃣ Time Windows (Sliding Windows)
   - bin(TimeGenerated, 5m): Group events into 5-min buckets
   - Use: Detect brute force (>10 attempts in 5 min)

4️⃣ Threshold Logic
   - where count_ > 10: Only alert if count exceeds threshold
   - Reduces false positives

5️⃣ Project Relevant Fields
   - Only include fields needed for investigation
   - Don't: Select all fields (performance impact)
   - Do: Select User, IP, Time, Count, etc.
```

### 10.3 Real-World Detection Examples

**Example 1: Brute Force Attack Detection**

```kql
// Detect: Multiple failed login attempts in short time

SecurityEvent
| where TimeGenerated > ago(5m)  // Last 5 minutes
| where EventID == 4625  // Failed logon events
| where AccountType == "User"  // Exclude computer accounts
| summarize 
    FailedAttempts = count(),
    TargetAccounts = make_set(TargetUserName),
    SourceIPs = make_set(IpAddress),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 10  // Threshold: >10 failed attempts
| project 
    Computer, 
    FailedAttempts, 
    TargetAccounts, 
    SourceIPs, 
    FirstAttempt, 
    LastAttempt
| extend AttackDuration = LastAttempt - FirstAttempt

Rule Configuration:
├─ Query frequency: 5 minutes
├─ Lookup period: 5 minutes
├─ Alert threshold: Greater than 0 (threshold in query)
├─ Severity: High
├─ Tactics: Credential Access (MITRE ATT&CK TA0006)
└─ Techniques: Brute Force (T1110)
```

**Example 2: Suspicious PowerShell Execution**

```kql
// Detect: Encoded PowerShell commands (obfuscation technique)

SecurityEvent
| where TimeGenerated > ago(1h)  // Last hour
| where EventID == 4688  // Process creation
| where Process has "powershell.exe"
| where CommandLine has_any (
    "-enc",           // Encoded command
    "-encodedcommand",
    "FromBase64String",
    "Invoke-Expression",
    "IEX",
    "DownloadString"  // Download from internet
  )
| extend 
    CommandLength = strlen(CommandLine),
    HasObfuscation = case(
        CommandLine contains "^" or CommandLine contains "``", "Yes",
        "No"
    )
| where CommandLength > 100 or HasObfuscation == "Yes"
| project 
    TimeGenerated,
    Computer,
    Account,
    Process,
    CommandLine,
    CommandLength,
    HasObfuscation,
    ParentProcessName
| extend AccountCustomEntity = Account, HostCustomEntity = Computer

Rule Configuration:
├─ Query frequency: 1 hour
├─ Lookup period: 1 hour
├─ Alert threshold: Greater than 0
├─ Severity: Medium
├─ Tactics: Execution (TA0002), Defense Evasion (TA0005)
└─ Techniques: PowerShell (T1059.001), Obfuscation (T1027)
```

**Example 3: Impossible Travel Detection**

```kql
// Detect: User signs in from two distant locations in short time

let LookbackPeriod = 6h;
let TravelThresholdKM = 500;  // 500 km in 1 hour = impossible

SigninLogs
| where TimeGenerated > ago(LookbackPeriod)
| where ResultType == 0  // Successful sign-ins only
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    LocationDetails = parse_json(LocationDetails),
    City = tostring(parse_json(LocationDetails).city),
    State = tostring(parse_json(LocationDetails).state),
    Country = tostring(parse_json(LocationDetails).countryOrRegion),
    Latitude = toreal(parse_json(LocationDetails).geoCoordinates.latitude),
    Longitude = toreal(parse_json(LocationDetails).geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| extend PreviousSignIn = prev(TimeGenerated, 1, TimeGenerated)
| extend PreviousLocation = prev(Location, 1, Location)
| extend PreviousCity = prev(City, 1, City)
| extend PreviousLatitude = prev(Latitude, 1, Latitude)
| extend PreviousLongitude = prev(Longitude, 1, Longitude)
| where TimeGenerated != PreviousSignIn  // Exclude first sign-in per user
| extend 
    TimeDiff = datetime_diff('minute', TimeGenerated, PreviousSignIn),
    DistanceKM = geo_distance_2points(
        PreviousLongitude, PreviousLatitude, 
        Longitude, Latitude
    ) / 1000  // Convert meters to kilometers
| where DistanceKM > TravelThresholdKM
| extend TravelSpeedKMH = DistanceKM / (TimeDiff / 60)  // KM per hour
| where TravelSpeedKMH > 500  // Impossible speed (>500 km/h)
| project 
    TimeGenerated,
    UserPrincipalName,
    CurrentCity = City,
    CurrentCountry = Country,
    PreviousCity,
    DistanceKM,
    TimeDiff,
    TravelSpeedKMH,
    CurrentIP = IPAddress
| extend AccountCustomEntity = UserPrincipalName, IPCustomEntity = CurrentIP

Rule Configuration:
├─ Query frequency: 6 hours
├─ Lookup period: 6 hours
├─ Alert threshold: Greater than 0
├─ Severity: Medium
├─ Tactics: Initial Access (TA0001)
└─ Techniques: Valid Accounts (T1078), Credential Theft
```

**Example 4: Privileged Account Creation**

```kql
// Detect: New user added to privileged groups (Domain Admins, etc.)

SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4728, 4732, 4756)  // Member added to group
| where TargetUserName in (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators"
  )  // Privileged groups only
| extend 
    AddedUser = SubjectUserName,
    AddedBy = Account,
    PrivilegedGroup = TargetUserName
| project 
    TimeGenerated,
    Computer,
    AddedUser,
    AddedBy,
    PrivilegedGroup,
    EventID
| extend 
    AccountCustomEntity = AddedUser,
    HostCustomEntity = Computer

Rule Configuration:
├─ Query frequency: 1 hour
├─ Lookup period: 1 hour
├─ Alert threshold: Greater than 0
├─ Severity: High
├─ Tactics: Persistence (TA0003), Privilege Escalation (TA0004)
└─ Techniques: Account Manipulation (T1098)
```

**Example 5: Mass File Deletion (Ransomware Indicator)**

```kql
// Detect: Large number of files deleted in short time (ransomware behavior)

OfficeActivity
| where TimeGenerated > ago(5m)
| where Operation == "FileDeleted"
| summarize 
    DeletedFiles = count(),
    FileNames = make_set(SourceFileName, 100),  // Sample file names
    Sites = make_set(SiteUrl, 10)
  by UserId, bin(TimeGenerated, 5m)
| where DeletedFiles > 100  // Threshold: >100 files in 5 min
| project 
    TimeGenerated,
    UserId,
    DeletedFiles,
    FileNames,
    Sites
| extend 
    AccountCustomEntity = UserId,
    AlertSeverity = case(
        DeletedFiles > 1000, "Critical",
        DeletedFiles > 500, "High",
        "Medium"
    )

Alternative (MDE - Device File Events):
DeviceFileEvents
| where TimeGenerated > ago(5m)
| where ActionType == "FileDeleted"
| summarize 
    DeletedFiles = count(),
    FolderPaths = make_set(FolderPath, 50)
  by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 5m)
| where DeletedFiles > 100
| project 
    TimeGenerated,
    DeviceName,
    Account = InitiatingProcessAccountName,
    DeletedFiles,
    FolderPaths
| extend 
    HostCustomEntity = DeviceName,
    AccountCustomEntity = Account

Rule Configuration:
├─ Query frequency: 5 minutes
├─ Lookup period: 5 minutes
├─ Alert threshold: Greater than 0
├─ Severity: High (dynamic based on count)
├─ Tactics: Impact (TA0040)
└─ Techniques: Data Destruction (T1485), Ransomware
```

**Example 6: Anomalous Sign-in Pattern (Geographic Anomaly)**

```kql
// Detect: Sign-in from location never seen before (30-day baseline)

let LookbackPeriod = 30d;
let DetectionPeriod = 1h;

// Step 1: Build baseline (locations seen in last 30 days)
let BaselineLocations = SigninLogs
| where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionPeriod))
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| summarize BaselineCountries = make_set(Country) by UserPrincipalName;

// Step 2: Detect sign-ins from new locations (last 1 hour)
SigninLogs
| where TimeGenerated > ago(DetectionPeriod)
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| join kind=leftouter (BaselineLocations) on UserPrincipalName
| extend IsNewCountry = case(
    isempty(BaselineCountries), true,  // First time seeing this user
    not(set_has_element(BaselineCountries, Country)), true,  // New country
    false
  )
| where IsNewCountry == true
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    City = tostring(parse_json(LocationDetails).city),
    Application = AppDisplayName,
    DeviceDetail = DeviceDetail
| extend 
    AccountCustomEntity = UserPrincipalName,
    IPCustomEntity = IPAddress

Rule Configuration:
├─ Query frequency: 1 hour
├─ Lookup period: 1 hour (query handles 30-day baseline internally)
├─ Alert threshold: Greater than 0
├─ Severity: Low (may be legitimate travel)
├─ Tactics: Initial Access (TA0001)
└─ Techniques: Valid Accounts (T1078)
```

### 10.4 Advanced KQL Techniques

**Technique 1: Behavioral Baselining**

```kql
// Detect: User accessing unusual number of files (deviation from baseline)

let BaselinePeriod = 14d;
let DetectionPeriod = 1h;
let DeviationThreshold = 3;  // 3x standard deviation

// Step 1: Calculate baseline (average + stddev per user)
let Baseline = OfficeActivity
| where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionPeriod))
| where Operation in ("FileAccessed", "FileDownloaded")
| summarize 
    AvgFiles = avg(count_),
    StdDevFiles = stdev(count_)
  by UserId, bin(TimeGenerated, 1h)
| summarize 
    AvgDailyFiles = avg(AvgFiles),
    StdDevDailyFiles = avg(StdDevFiles)
  by UserId;

// Step 2: Compare current activity to baseline
OfficeActivity
| where TimeGenerated > ago(DetectionPeriod)
| where Operation in ("FileAccessed", "FileDownloaded")
| summarize CurrentFiles = count() by UserId
| join kind=inner (Baseline) on UserId
| extend 
    UpperThreshold = AvgDailyFiles + (DeviationThreshold * StdDevDailyFiles),
    Deviation = (CurrentFiles - AvgDailyFiles) / StdDevDailyFiles
| where CurrentFiles > UpperThreshold  // Significantly higher than normal
| project 
    UserId,
    CurrentFiles,
    NormalAverage = AvgDailyFiles,
    Deviation,
    UpperThreshold
| extend AccountCustomEntity = UserId
```

**Technique 2: Threat Intelligence Correlation**

```kql
// Detect: Connections to malicious IPs (correlate with TI)

let TimeWindow = 1h;

// Get active malicious IPs from threat intel
let MaliciousIPs = ThreatIntelIndicators
| where TimeGenerated > ago(14d)
| where Active == true
| where NetworkIP != ""
| where ConfidenceScore > 70
| extend MaliciousIP = NetworkIP
| project MaliciousIP, ThreatType, Description, ConfidenceScore;

// Find connections to these IPs
CommonSecurityLog
| where TimeGenerated > ago(TimeWindow)
| where DeviceAction != "deny"  // Only successful connections
| extend ConnectedIP = DestinationIP
| join kind=inner (MaliciousIPs) on $left.ConnectedIP == $right.MaliciousIP
| project 
    TimeGenerated,
    SourceIP,
    ConnectedIP,
    SourcePort,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    ThreatType,
    Description,
    ConfidenceScore
| extend IPCustomEntity = ConnectedIP
```

**Technique 3: User Peer Group Analysis**

```kql
// Detect: User behavior different from peers (insider threat)

let DetectionPeriod = 1d;
let PeerGroupSize = 10;  // Compare to 10 similar users

// Define peer group (same department, role, etc.)
// Note: Requires enrichment data (Azure AD attributes)

SigninLogs
| where TimeGenerated > ago(DetectionPeriod)
| where ResultType == 0
| extend 
    Department = tostring(parse_json(UserProperties).department),
    JobTitle = tostring(parse_json(UserProperties).jobTitle)
| summarize 
    SignIns = count(),
    UniqueApps = dcount(AppDisplayName),
    UniqueLocations = dcount(Location)
  by UserPrincipalName, Department, JobTitle
// Calculate peer averages (same department + job title)
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(DetectionPeriod)
    | where ResultType == 0
    | extend 
        Department = tostring(parse_json(UserProperties).department),
        JobTitle = tostring(parse_json(UserProperties).jobTitle)
    | summarize 
        PeerSignIns = count(),
        PeerUniqueApps = dcount(AppDisplayName)
      by Department, JobTitle
    | summarize 
        AvgPeerSignIns = avg(PeerSignIns),
        AvgPeerApps = avg(PeerUniqueApps)
      by Department, JobTitle
  ) on Department, JobTitle
| extend 
    SignInDeviation = (SignIns - AvgPeerSignIns) / AvgPeerSignIns * 100,
    AppDeviation = (UniqueApps - AvgPeerApps) / AvgPeerApps * 100
| where SignInDeviation > 200 or AppDeviation > 200  // 200% more than peers
| project 
    UserPrincipalName,
    Department,
    JobTitle,
    SignIns,
    PeerAverage = AvgPeerSignIns,
    SignInDeviation,
    UniqueApps,
    PeerAvgApps = AvgPeerApps,
    AppDeviation
```

**🎯 Exam Tip:**
- **Scheduled rules**: Most flexible, full KQL capabilities, 5 min to 14 days frequency
- **Query frequency ≤ Lookup period**: Avoid data gaps (5-min rule should look back ≥5 min)
- **Filter early**: where clauses at top (performance optimization)
- **Aggregation**: summarize to detect patterns (count, dcount, make_set)
- **Time windows**: bin(TimeGenerated, 5m) for sliding window detection
- **Thresholds**: where count_ > 10 (reduce false positives)
- **Common use cases**: Brute force (Event ID 4625), PowerShell (4688), privileged access (4728/4732), impossible travel, mass deletion
- **Advanced techniques**: Behavioral baselining (avg + stddev), TI correlation (join with ThreatIntelIndicators), peer group analysis

---

## 11. Near-Real-Time (NRT) Rules

### 11.1 NRT Rule Overview

**Sub-Minute Detection for Critical Threats:**

```
Near-Real-Time (NRT) Rule:
- Runs: Every 1 minute (fixed interval)
- Latency: 1-10 minutes from event to alert
- Logic: Simplified KQL (limited operators)
- Limit: 50 NRT rules per workspace (hard limit)

When to Use NRT Rules:
✅ Time-critical threats (break glass account access)
✅ High-value targets (admin accounts, executives)
✅ Regulatory requirements (immediate detection)
✅ Known attack patterns (specific Event IDs)

When NOT to Use:
❌ Complex queries (joins, aggregations limited)
❌ Baseline/behavioral analysis (use Scheduled rules)
❌ Low-priority threats (5-min Scheduled rule sufficient)
❌ High-volume detection (exceeds 50 rule limit)

NRT vs Scheduled (5-min):
┌────────────────────────────────────────────────────────┐
│ Aspect          | NRT (1-min)    | Scheduled (5-min)   │
├────────────────────────────────────────────────────────┤
│ Execution       | Every 1 minute | Every 5+ minutes    │
│ Latency         | 1-10 minutes   | 5-15 minutes        │
│ KQL Complexity  | Limited        | Full capabilities   │
│ Workspace Limit | 50 rules max   | Unlimited           │
│ Use Case        | Critical only  | All other detections│
└────────────────────────────────────────────────────────┘
```

### 11.2 NRT Rule Limitations

**KQL Operator Restrictions:**

```
✅ Supported Operators (NRT Rules):
├─ where: Filtering (all comparison operators)
├─ extend: Add calculated columns
├─ project: Select columns
├─ project-away: Exclude columns
├─ project-rename: Rename columns
├─ parse: Extract fields from text
├─ join (limited): Only inner join on single key
└─ lookup (limited): Only left outer lookup

❌ NOT Supported Operators:
├─ summarize: Aggregation (count, sum, avg, etc.)
├─ make_set / make_list: Array creation
├─ bin(): Time windowing
├─ mv-expand: Array expansion
├─ join (complex): Multiple keys, all join types except inner
├─ union: Combining multiple tables
├─ Functions: Custom functions (saved queries)
├─ externaldata: External data sources
└─ Advanced KQL: ago() with dynamic time, complex logic

Workarounds:

Problem: Need to count events (summarize not allowed)
Solution 1: Use Scheduled rule (5-min) with aggregation
Solution 2: Use Anomaly rule (ML-based, no KQL needed)

Problem: Need to group by user (summarize not allowed)
Solution: Project all relevant fields, group in incident (multiple alerts → 1 incident)

Problem: Need complex join (multiple tables)
Solution: Use Scheduled rule (more complex logic allowed)
```

### 11.3 NRT Rule Examples

**Example 1: Break Glass Account Access**

```kql
// Detect: Immediate alert when emergency admin account used

SigninLogs
| where ResultType == 0  // Successful sign-in
| where UserPrincipalName in (
    "breakglass1@contoso.com",
    "breakglass2@contoso.com"
  )  // Break glass accounts (emergency use only)
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    City = tostring(parse_json(LocationDetails).city),
    Country = tostring(parse_json(LocationDetails).countryOrRegion),
    AppDisplayName,
    UserAgent,
    DeviceDetail
| extend 
    AccountCustomEntity = UserPrincipalName,
    IPCustomEntity = IPAddress

Rule Configuration:
├─ Rule type: Near-Real-Time (NRT)
├─ Severity: Critical
├─ Tactics: Persistence (TA0003), Privilege Escalation (TA0004)
├─ Techniques: Valid Accounts (T1078)
├─ Automation: Trigger playbook (send urgent alert to SOC + CISO)
└─ Note: 1-minute execution, immediate notification
```

**Example 2: Admin Account Created**

```kql
// Detect: New admin account creation (high-risk event)

AuditLogs
| where TimeGenerated > ago(2m)  // Look back 2 min (NRT buffer)
| where OperationName == "Add member to role"
| where TargetResources has_any (
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator"
  )  // High-privilege roles
| extend 
    AddedUser = tostring(TargetResources[0].userPrincipalName),
    AddedBy = tostring(InitiatedBy.user.userPrincipalName),
    Role = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project 
    TimeGenerated,
    AddedUser,
    AddedBy,
    Role,
    IPAddress = tostring(InitiatedBy.user.ipAddress),
    CorrelationId
| extend 
    AccountCustomEntity = AddedUser,
    IPCustomEntity = IPAddress

Rule Configuration:
├─ Rule type: Near-Real-Time (NRT)
├─ Severity: High
├─ Tactics: Persistence (TA0003), Privilege Escalation (TA0004)
├─ Techniques: Account Manipulation (T1098)
└─ Automation: Disable new admin (if unauthorized), notify security team
```

**Example 3: Malicious File Hash Detected**

```kql
// Detect: File execution matching known malware hash (TI match)

let MaliciousHashes = ThreatIntelIndicators
| where Active == true
| where FileHashValue != ""
| where ThreatType has_any ("malware", "trojan", "ransomware")
| project FileHashValue;

DeviceFileEvents
| where ActionType == "FileCreated"
| where SHA256 in (MaliciousHashes)
| project 
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessAccountName,
    InitiatingProcessFileName
| join kind=inner (ThreatIntelIndicators) on $left.SHA256 == $right.FileHashValue
| project 
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    Account = InitiatingProcessAccountName,
    ThreatType,
    Description
| extend 
    HostCustomEntity = DeviceName,
    FileHashCustomEntity = SHA256,
    AccountCustomEntity = Account

Rule Configuration:
├─ Rule type: Near-Real-Time (NRT)
├─ Severity: Critical
├─ Tactics: Execution (TA0002)
├─ Techniques: Malicious File (T1204)
└─ Automation: Isolate device (MDE), quarantine file, notify SOC
```

**Example 4: Privileged Command Execution**

```kql
// Detect: Sensitive commands executed (immediate visibility)

SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine has_any (
    "net user",        // User management
    "net localgroup",  // Group management
    "reg add",         // Registry modification
    "sc create",       // Service creation
    "schtasks",        // Task scheduler
    "psexec",          // Lateral movement tool
    "mimikatz",        // Credential dumping
    "procdump"         // Memory dumping
  )
| project 
    TimeGenerated,
    Computer,
    Account,
    Process,
    CommandLine,
    ParentProcessName,
    ProcessId
| extend 
    HostCustomEntity = Computer,
    AccountCustomEntity = Account,
    ProcessCustomEntity = Process

Rule Configuration:
├─ Rule type: Near-Real-Time (NRT)
├─ Severity: High
├─ Tactics: Execution (TA0002), Credential Access (TA0006)
├─ Techniques: PowerShell (T1059.001), Credential Dumping (T1003)
└─ Automation: Create high-priority incident, alert analyst immediately
```

**Example 5: VIP User Sign-in from High-Risk IP**

```kql
// Detect: C-level executive sign-in from risky IP (compromised account)

let VIPUsers = dynamic([
    "ceo@contoso.com",
    "cfo@contoso.com",
    "ciso@contoso.com"
]);  // VIP accounts

SigninLogs
| where ResultType == 0
| where UserPrincipalName in (VIPUsers)
| where RiskLevelDuringSignIn in ("high", "medium")  // Entra ID Protection risk
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    RiskLevelDuringSignIn,
    RiskDetail,
    AppDisplayName,
    DeviceDetail
| extend 
    AccountCustomEntity = UserPrincipalName,
    IPCustomEntity = IPAddress

Alternative (Threat Intel Correlation):
let VIPUsers = dynamic(["ceo@contoso.com", "cfo@contoso.com"]);
let MaliciousIPs = ThreatIntelIndicators
| where Active == true
| where NetworkIP != ""
| project NetworkIP;

SigninLogs
| where ResultType == 0
| where UserPrincipalName in (VIPUsers)
| where IPAddress in (MaliciousIPs)
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName
| join kind=inner (ThreatIntelIndicators) on $left.IPAddress == $right.NetworkIP
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    ThreatType,
    Description
| extend 
    AccountCustomEntity = UserPrincipalName,
    IPCustomEntity = IPAddress

Rule Configuration:
├─ Rule type: Near-Real-Time (NRT)
├─ Severity: High
├─ Tactics: Initial Access (TA0001)
├─ Techniques: Valid Accounts (T1078), Credential Theft
└─ Automation: Disable account, force password reset, notify security + user
```

### 11.4 NRT Best Practices

**Optimizing NRT Rules:**

```
Best Practices:

1️⃣ Reserve for Critical Detections Only
   ✅ Break glass accounts
   ✅ Admin privilege changes
   ✅ VIP user activities
   ❌ Routine security events (use Scheduled rules)

2️⃣ Keep Queries Simple
   ✅ Single table queries (avoid joins if possible)
   ✅ Direct filtering (where clauses)
   ❌ Complex logic, multiple joins, aggregations

3️⃣ Use Dynamic Lists for Flexibility
   let VIPUsers = dynamic(["user1@...", "user2@..."]);
   - Easy to update (no rule modification needed)
   - Consistent across rules

4️⃣ Monitor NRT Rule Limit (50 Max)
   - Track: How many NRT rules deployed
   - Prioritize: Convert low-priority NRT → Scheduled (5-min)
   - Review: Quarterly review of NRT rule necessity

5️⃣ Combine with Automation
   - NRT rules = Fast detection
   - Playbooks = Fast response
   - Together = Sub-5-minute MTTR (Mean Time To Respond)

6️⃣ Test Before Production
   - Test query: Run manually in Logs (verify results)
   - Test frequency: Does 1-min execution make sense?
   - Test volume: Will rule generate too many alerts?

7️⃣ Document Justification
   - Why NRT? (not Scheduled 5-min?)
   - Business impact: What's the risk if delayed?
   - Incident response: What happens when alert fires?

Example Decision Matrix:
┌────────────────────────────────────────────────────────┐
│ Scenario              | NRT? | Scheduled? | Why?      │
├────────────────────────────────────────────────────────┤
│ Break glass account   | ✅   | ❌         | Critical  │
│ Admin role added      | ✅   | ❌         | High risk │
│ VIP sign-in anomaly   | ✅   | ❌         | Executive │
│ Brute force (general) | ❌   | ✅ (5-min) | Not urgent│
│ Impossible travel     | ❌   | ✅ (1-hour)| Baseline  │
│ Mass file deletion    | ✅   | ❌         | Ransomware│
└────────────────────────────────────────────────────────┘
```

**🎯 Exam Tip:**
- **NRT rules**: 1-minute execution, 1-10 min latency, 50 rules max per workspace
- **Limitations**: No summarize (aggregation), limited joins, no functions
- **Use cases**: Break glass accounts, admin privilege changes, VIP activities, malware hash matches
- **Best practice**: Reserve for critical only (not routine detections)
- **Query design**: Simple, single-table, direct filtering (avoid complexity)
- **Comparison**: NRT (1-min, limited KQL) vs Scheduled (5-min+, full KQL)
- **Exam scenario**: "Immediate detection required" → Choose NRT rule

---

## 12. Advanced Rule Types

### 12.1 Anomaly Detection Rules

**Machine Learning-Based Detection:**

```
Anomaly Detection Rule:
- Method: Machine Learning (unsupervised learning)
- Detection: Baseline normal behavior → Alert on deviations
- Learning period: 30 days (establish baseline)
- Configuration: Templates (Microsoft-provided, no KQL needed)
- Tuning: Threshold (sensitivity) adjustment

How It Works:
1. Learning phase: 30 days to learn normal patterns
   - User behavior: Typical sign-in times, locations, apps
   - Device behavior: Typical processes, network connections
   - Entity behavior: Typical file access patterns

2. Detection phase: After 30 days, start alerting
   - Compare: Current activity vs baseline
   - Deviation: Statistical anomaly (multiple standard deviations)
   - Alert: If deviation significant (high confidence)

3. Continuous learning: Baseline updates automatically
   - Adapts: To changing behavior (new normal)
   - Avoids: False positives from legitimate changes

Types of Anomalies Detected:
├─ Temporal: Activity at unusual time (3am sign-in for 9-5 user)
├─ Geographic: Sign-in from unusual location
├─ Behavioral: Unusual app usage, file access patterns
├─ Volume: Abnormal number of activities (10x normal)
└─ Sequential: Unusual sequence of events
```

**Built-in Anomaly Templates:**

```
Microsoft-Provided Anomaly Rules (Content Hub):

1️⃣ Anomalous Sign-in Pattern
   - Detects: Unusual sign-in behavior (time, location, frequency)
   - Learning: User sign-in patterns (30 days)
   - Baseline: Typical hours, days, locations
   - Alert: Deviation from norm (e.g., 3am sign-in for 9-5 user)

2️⃣ Anomalous Access Pattern
   - Detects: Unusual file/resource access
   - Learning: User access patterns (30 days)
   - Baseline: Typical files, folders, sites accessed
   - Alert: Access to unusual resources (sensitive files)

3️⃣ Anomalous Account Activity
   - Detects: Unusual account management actions
   - Learning: Admin activity patterns (30 days)
   - Baseline: Typical user/group changes
   - Alert: Unusual admin actions (mass user creation)

4️⃣ Anomalous Network Activity
   - Detects: Unusual network connections (devices)
   - Learning: Device network patterns (30 days)
   - Baseline: Typical destinations, protocols, ports
   - Alert: Connection to unusual IPs/domains

Configuration:

Step 1: Enable Anomaly Rule (Content Hub)
─────────────────────────────────────────
Sentinel → Content hub → Search "Anomaly"
→ Install "Anomaly Detection" solution

Step 2: Configure Threshold (Sensitivity)
─────────────────────────────────────────
Sentinel → Analytics → Anomaly rules

Threshold Options:
├─ Low: More alerts (higher sensitivity, more false positives)
├─ Medium: Balanced (recommended starting point)
└─ High: Fewer alerts (lower sensitivity, fewer false positives)

Recommendation: Start with Medium, tune based on alert volume

Step 3: Wait for Learning Period
─────────────────────────────────────────
- Duration: 30 days (minimum)
- During: No alerts (still learning)
- After: Alerts start generating

Step 4: Tune Based on Feedback
─────────────────────────────────────────
- Review: Anomaly alerts (true positive rate)
- Adjust: Threshold (increase if too many FPs)
- Feedback: Mark alerts as "benign" (improves ML model)
```

**Anomaly Rule Example (Sign-in):**

```
Rule Name: "Anomalous Sign-in Activity"

Detection Logic (Automated by ML):
1. Baseline: User signs in Mon-Fri, 9am-5pm, from Office IP
2. Anomaly: User signs in Sunday, 3am, from residential IP
3. Scoring: Calculate anomaly score (0-100)
   - Time deviation: +50 (unusual time)
   - Day deviation: +30 (unusual day)
   - Location deviation: +20 (unusual IP)
   - Total: 100 (high anomaly score)
4. Alert: If score > threshold (e.g., >70), generate alert

Alert Details (Automatic):
├─ Title: "Anomalous sign-in activity for user@contoso.com"
├─ Description: "User signed in at unusual time (3am) from unusual location (home IP)"
├─ Severity: Medium (based on anomaly score)
├─ Entities: User, IP address, location
├─ Evidence: 
│  ├─ Baseline: Typical sign-in times (Mon-Fri, 9am-5pm)
│  ├─ Current: Actual sign-in time (Sunday, 3am)
│  └─ Deviation: Anomaly score (100/100)
└─ Investigation: Link to user activity timeline

No KQL Needed! ML model handles detection automatically.
```

**When to Use Anomaly Rules:**

```
✅ Use Anomaly Rules When:
├─ Unknown threats (no known pattern)
├─ Insider threats (behavioral changes)
├─ Zero-day attacks (no signature)
├─ Account compromise (unusual user behavior)
└─ Baseline available (stable environment, not new deployment)

❌ Don't Use Anomaly Rules When:
├─ Known threats (use Scheduled rules with specific logic)
├─ New environment (<30 days old, no baseline yet)
├─ High turnover (users frequently changing roles)
├─ Highly dynamic (behavior changes weekly)
└─ Need immediate detection (30-day learning period)

Comparison: Anomaly vs Scheduled Rules
┌────────────────────────────────────────────────────────┐
│ Aspect           | Anomaly        | Scheduled          │
├────────────────────────────────────────────────────────┤
│ Detection Method | ML (automatic) | KQL (manual)       │
│ Setup Time       | Minutes        | Hours (query dev)  │
│ Learning Period  | 30 days        | None               │
│ Maintenance      | Low            | High (tuning)      │
│ Unknown Threats  | ✅ Yes         | ❌ No (need pattern)│
│ Known Threats    | ❌ No          | ✅ Yes (specific)   │
│ Tuning           | Threshold only | Full query control │
└────────────────────────────────────────────────────────┘

Best Practice: Use BOTH
- Anomaly rules: Catch unknown/insider threats
- Scheduled rules: Catch known threats (brute force, etc.)
```

### 12.2 Fusion Rules

**Multi-Stage Attack Detection:**

```
Fusion Rule (ML Correlation Engine):
- Method: Machine Learning (Microsoft-developed)
- Detection: Correlates multiple weak signals → High-fidelity incidents
- Configuration: None (fully automated)
- Tuning: Sensitivity only (Low, Medium, High)

How Fusion Works:
1. Collect signals: From multiple sources (Entra ID, MDE, MDO, MDCA, Sentinel)
2. Correlate: ML model identifies attack chains
   - Signal 1: User sign-in from malicious IP (TI match)
   - Signal 2: User downloads unusual file (MDO)
   - Signal 3: User accesses 50 accounts (lateral movement)
3. Fusion: Correlates signals → Creates incident (not just alerts)
4. High fidelity: Fusion incidents = 80%+ true positive rate

Example Attack Chains Detected:
┌────────────────────────────────────────────────────────┐
│ Scenario: Compromised Account + Data Exfiltration     │
├────────────────────────────────────────────────────────┤
│ 1. Impossible travel: Sign-in from 2 distant locations│
│ 2. Mass download: 100+ files downloaded in 10 minutes │
│ 3. External sharing: Files shared to external domain  │
│ → Fusion: "Potential data exfiltration" incident      │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Scenario: Credential Access + Lateral Movement        │
├────────────────────────────────────────────────────────┤
│ 1. Malicious IP: Sign-in from known attacker IP (TI)  │
│ 2. Credential dump: Mimikatz execution detected (MDE) │
│ 3. Lateral movement: RDP to 20 servers in 5 minutes   │
│ → Fusion: "Advanced persistent threat" incident       │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Scenario: Phishing + Malware + C2 Communication       │
├────────────────────────────────────────────────────────┤
│ 1. Phishing: Suspicious email link clicked (MDO)      │
│ 2. Malware: Malicious file executed (MDE)             │
│ 3. C2: Connection to known C2 domain (firewall)       │
│ → Fusion: "Malware infection with C2" incident        │
└────────────────────────────────────────────────────────┘
```

**Fusion Configuration:**

```
Step 1: Enable Fusion Rule
─────────────────────────────────────────
Sentinel → Analytics → Fusion

Status: Enabled by default (no configuration needed)

Step 2: Configure Sensitivity (Tuning)
─────────────────────────────────────────
Sensitivity Levels:
├─ High: Fewer incidents (only high-confidence attack chains)
├─ Medium: Balanced (recommended)
└─ Low: More incidents (lower confidence, more false positives)

Recommendation: Start with Medium, adjust based on incident volume

Step 3: Review Fusion Incidents
─────────────────────────────────────────
Sentinel → Incidents → Filter by "Detection source: Fusion"

Incident Details:
├─ Title: Attack scenario (e.g., "Potential data exfiltration")
├─ Severity: Medium or High (based on attack chain)
├─ Alerts: Multiple alerts from different sources (correlated)
├─ Timeline: Chronological view of attack chain
├─ Investigation graph: Visual representation of attack
└─ Recommendations: Suggested remediation steps

Step 4: No Maintenance Required
─────────────────────────────────────────
- Fusion auto-updates (Microsoft-managed ML models)
- No KQL queries to maintain
- No tuning beyond sensitivity
```

**Fusion Data Sources:**

```
Fusion Correlates Data From:

✅ Microsoft Sentinel:
├─ Analytics rules (Scheduled, NRT, Anomaly)
├─ Threat intelligence (TI matches)
└─ Custom detections

✅ Microsoft Entra ID (Azure AD):
├─ Sign-in logs (impossible travel, risky sign-ins)
├─ Identity Protection (risk detections)
└─ Conditional Access (policy violations)

✅ Microsoft Defender for Endpoint (MDE):
├─ Device alerts (malware, suspicious processes)
├─ Advanced Hunting (behavioral detections)
└─ Automated investigations

✅ Microsoft Defender for Office 365 (MDO):
├─ Email threats (phishing, malware)
├─ Safe Links/Attachments (clicks, detonations)
└─ User-reported messages

✅ Microsoft Defender for Cloud Apps (MDCA):
├─ Cloud app activities (unusual access)
├─ OAuth app detections (risky apps)
└─ DLP alerts (data leakage)

✅ Azure Defender / Defender for Cloud:
├─ VM alerts (unusual processes, network activity)
├─ SQL alerts (suspicious queries, brute force)
└─ Key Vault alerts (unauthorized access)

Fusion Strength: Cross-product correlation
- Single-product alert: May be false positive
- Multi-product correlation: High confidence (true positive)
```

**Fusion Benefits:**

```
Why Use Fusion?

1️⃣ Reduce False Positives
   - Single alerts: Often benign (user traveling, legitimate file download)
   - Fusion incidents: Multiple correlated signals = high confidence

2️⃣ Detect Advanced Attacks
   - Sophisticated attackers: Use multi-stage techniques
   - Single detection: May miss attack chain
   - Fusion: Connects the dots (full attack picture)

3️⃣ No Maintenance
   - Scheduled rules: Require tuning, maintenance
   - Fusion: Auto-updates (Microsoft-managed ML models)

4️⃣ Faster Investigation
   - Manual correlation: Analyst spends hours connecting alerts
   - Fusion: Automatic correlation (investigation graph, timeline)

5️⃣ High-Fidelity Incidents
   - False positive rate: <20% (80%+ true positives)
   - Compare: Scheduled rules often 50-70% FP rate

Statistics (Microsoft):
- Fusion detection rate: 80%+ true positive
- Investigation time: 60% reduction (automatic correlation)
- Alert fatigue: 70% reduction (fewer, high-quality incidents)
```

**🎯 Exam Tip:**
- **Anomaly rules**: ML-based, 30-day learning period, no KQL needed
- **Use cases**: Unknown threats, insider threats, behavioral anomalies
- **Tuning**: Threshold (sensitivity) only (Low, Medium, High)
- **Fusion**: ML correlation engine, multi-stage attack detection, enabled by default
- **Fusion benefits**: High fidelity (80%+ true positive), no maintenance, reduces alert fatigue
- **Fusion data sources**: Sentinel, Entra ID, MDE, MDO, MDCA, Defender for Cloud (cross-product)
- **Best practice**: Enable both Anomaly + Fusion (complement Scheduled rules)
- **Exam scenario**: "Detect unknown multi-stage attacks" → Choose Fusion rule

---

## 13. Entity Mapping

### 13.1 What is Entity Mapping?

**Linking Alerts to Real-World Objects:**

```
Entity Mapping:
- Definition: Map query results to real-world entities (users, IPs, hosts, files)
- Purpose: Enable correlation, investigation, timeline, graph
- Entities: Account, Host, IP, File, URL, Process, Mailbox, CloudApp, etc.

Why Entity Mapping Matters:

Without Entity Mapping:
❌ Alert: "Suspicious activity detected"
❌ Investigation: Analyst must manually identify user, IP, host
❌ Correlation: Cannot link related alerts (same user, different incidents)
❌ Timeline: No entity activity history
❌ Graph: No relationship visualization

With Entity Mapping:
✅ Alert: "User john@contoso.com from IP 203.0.113.50 on host DESKTOP-123"
✅ Investigation: Click entity → See all activities (automatic)
✅ Correlation: Link incidents by entity (same user attacked multiple times)
✅ Timeline: Complete activity history for entity
✅ Graph: Visual relationships (user → IP → host → file)

Entity Mapping Benefits:
1. Faster investigation: One-click entity details
2. Better correlation: Group related alerts (same entity)
3. Incident enrichment: Automatic entity context
4. Investigation graph: Visual attack chain
5. UEBA integration: Entity risk scores
6. Threat intelligence: Correlate IoCs with entities
```

### 13.2 Entity Types

**Supported Entity Types in Sentinel:**

```
Common Entity Types (SC-200 Focus):

1️⃣ Account
   ├─ Fields: Name, UPNSuffix, AadUserId, Sid, ObjectGuid
   ├─ Example: john@contoso.com, CONTOSO\john
   ├─ Use: User activities, sign-ins, file access
   └─ Sources: SigninLogs, SecurityEvent, AuditLogs

2️⃣ Host (Computer/Device)
   ├─ Fields: HostName, NetBiosName, DnsDomain, AzureID, OMSAgentID
   ├─ Example: DESKTOP-123, server01.contoso.com
   ├─ Use: Device activities, malware, lateral movement
   └─ Sources: SecurityEvent, DeviceEvents, Heartbeat

3️⃣ IP Address
   ├─ Fields: Address (IPv4 or IPv6)
   ├─ Example: 203.0.113.50, 2001:0db8::1
   ├─ Use: Network connections, sign-ins, threat intel
   └─ Sources: SigninLogs, CommonSecurityLog, NetworkEvents

4️⃣ File
   ├─ Fields: Name, Directory (path)
   ├─ Example: malware.exe, C:\Windows\Temp\payload.dll
   ├─ Use: Malware detection, file access, DLP
   └─ Sources: DeviceFileEvents, SecurityEvent (4663)

5️⃣ FileHash
   ├─ Fields: Algorithm (MD5, SHA1, SHA256), Value
   ├─ Example: SHA256:abc123...
   ├─ Use: Malware detection, threat intelligence
   └─ Sources: DeviceFileEvents, ThreatIntelIndicators

6️⃣ Process
   ├─ Fields: ProcessId, CommandLine, CreationTimeUtc
   ├─ Example: powershell.exe -enc <base64>
   ├─ Use: Process execution, command line analysis
   └─ Sources: SecurityEvent (4688), DeviceProcessEvents

7️⃣ URL
   ├─ Fields: Url (full URL)
   ├─ Example: https://evil.com/payload
   ├─ Use: Phishing, malicious links, C2 detection
   └─ Sources: EmailUrlInfo, UrlClickEvents

8️⃣ Mailbox
   ├─ Fields: MailboxPrimaryAddress, DisplayName, Upn
   ├─ Example: john@contoso.com
   ├─ Use: Email threats, phishing, business email compromise
   └─ Sources: EmailEvents, OfficeActivity

9️⃣ CloudApplication
   ├─ Fields: AppId, Name, InstanceName
   ├─ Example: Office 365, Salesforce, GitHub
   ├─ Use: Cloud app activities, OAuth, shadow IT
   └─ Sources: CloudAppEvents, SigninLogs

🔟 RegistryKey / RegistryValue
   ├─ Fields: Hive, Key, Value
   ├─ Example: HKLM\Software\Microsoft\...
   ├─ Use: Persistence, registry modifications
   └─ Sources: DeviceRegistryEvents, SecurityEvent

Full list: 20+ entity types (including Azure Resource, DNS, IoT Device, etc.)
```

### 13.3 Entity Mapping Configuration

**How to Map Entities in Analytics Rules:**

```
Step 1: Design Query with Entity Fields
─────────────────────────────────────────
Ensure query results include entity identifiers

Example Query:
SigninLogs
| where ResultType != 0  // Failed sign-ins
| project 
    TimeGenerated,
    UserPrincipalName,  // ← Account entity
    IPAddress,          // ← IP entity
    Location,
    AppDisplayName
| summarize FailedLogins = count() by UserPrincipalName, IPAddress
| where FailedLogins > 10

Step 2: Configure Entity Mapping (Analytics Rule Wizard)
─────────────────────────────────────────
Portal: Sentinel → Analytics → Create/Edit Rule → Entity mapping

Mapping Configuration:
┌────────────────────────────────────────────────────────┐
│ Entity Type: Account                                   │
│ Identifier: FullName                                   │
│ Value: UserPrincipalName (column from query)          │
├────────────────────────────────────────────────────────┤
│ Entity Type: IP                                        │
│ Identifier: Address                                    │
│ Value: IPAddress (column from query)                  │
└────────────────────────────────────────────────────────┘

Result: Alerts will have Account and IP entities mapped

Step 3: Use extend for Entity Naming (Recommended)
─────────────────────────────────────────
Use standard suffix: *CustomEntity (Sentinel convention)

Query with Entity Naming:
SigninLogs
| where ResultType != 0
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName
| summarize FailedLogins = count() by UserPrincipalName, IPAddress
| where FailedLogins > 10
| extend 
    AccountCustomEntity = UserPrincipalName,  // ← Naming convention
    IPCustomEntity = IPAddress                 // ← Naming convention

Entity Mapping (Automatic Detection):
- Sentinel auto-detects columns ending with "CustomEntity"
- Maps to appropriate entity type (based on suffix)
- Less configuration needed (wizard pre-filled)

Naming Conventions:
├─ AccountCustomEntity → Account
├─ HostCustomEntity → Host
├─ IPCustomEntity → IP
├─ FileCustomEntity → File
├─ FileHashCustomEntity → FileHash
├─ ProcessCustomEntity → Process
├─ URLCustomEntity → URL
└─ MailboxCustomEntity → Mailbox
```

### 13.4 Advanced Entity Mapping Examples

**Example 1: Multi-Entity Mapping (Complete Context)**

```kql
// Detect: Suspicious process execution with full context

SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine has_any ("powershell", "cmd", "wmic")
| where CommandLine contains "-enc" or CommandLine contains "IEX"
| project 
    TimeGenerated,
    Computer,
    Account,
    Process,
    CommandLine,
    ParentProcessName,
    ProcessId
| extend 
    HostCustomEntity = Computer,              // Host entity
    AccountCustomEntity = Account,            // Account entity
    ProcessCustomEntity = Process,            // Process entity
    CommandLineCustomEntity = CommandLine,    // Command line (for context)
    ProcessIdCustomEntity = tostring(ProcessId)  // Process ID

Entity Mapping Result:
Alert includes:
├─ Host: DESKTOP-123 (link to device details)
├─ Account: CONTOSO\john (link to user activities)
├─ Process: powershell.exe (link to process tree)
├─ Process ID: 1234 (for correlation)
└─ Command Line: Full command (evidence)

Investigation:
- Click "Host": See all activities on DESKTOP-123
- Click "Account": See all activities by user john
- Click "Process": See process execution timeline
```

**Example 2: File + FileHash Mapping (Malware Detection)**

```kql
// Detect: Malware execution (file hash match)

let MaliciousHashes = ThreatIntelIndicators
| where Active == true
| where FileHashValue != ""
| distinct FileHashValue;

DeviceFileEvents
| where ActionType == "FileCreated"
| where SHA256 in (MaliciousHashes)
| project 
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    FileOriginUrl,
    InitiatingProcessAccountName,
    InitiatingProcessFileName
| extend 
    HostCustomEntity = DeviceName,                    // Host
    AccountCustomEntity = InitiatingProcessAccountName, // Account
    FileCustomEntity = FileName,                       // File
    FileHashCustomEntity = SHA256,                     // FileHash (for TI lookup)
    DirectoryCustomEntity = FolderPath,                // File path
    URLCustomEntity = FileOriginUrl                    // Download URL (if available)

Investigation:
- FileHash entity: Automatic TI lookup (malicious? known malware?)
- File entity: Where is file now? (quarantined?)
- Host entity: Other malware on this device?
- Account entity: Compromised? Other suspicious activities?
```

**Example 3: Email Phishing (Multiple Entities)**

```kql
// Detect: Phishing email with malicious link

EmailUrlInfo
| where Url has_any ("evil.com", "phishing.net")  // Known phishing domains
| join kind=inner (
    EmailEvents
    | where EmailDirection == "Inbound"
  ) on NetworkMessageId
| project 
    TimeGenerated,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderIPv4,
    Subject,
    Url,
    UrlLocation,
    DeliveryAction
| extend 
    MailboxCustomEntity = RecipientEmailAddress,      // Recipient mailbox
    AccountCustomEntity = RecipientEmailAddress,      // Recipient account
    SenderAccountCustomEntity = SenderFromAddress,    // Sender account
    IPCustomEntity = SenderIPv4,                       // Sender IP
    URLCustomEntity = Url                              // Malicious URL

Investigation:
- Mailbox: Did recipient click link? (UrlClickEvents)
- URL: Known phishing? (TI lookup)
- Sender IP: Known attacker? (TI lookup, WHOIS)
- Recipient: Other phishing emails received?
```

### 13.5 Investigation Graph (Entity Relationships)

**Visual Investigation with Entity Mapping:**

```
Investigation Graph:
- Visual representation of entity relationships
- Automatic: Generated from entity mapping
- Interactive: Click entities to explore

Example Attack Chain (Graph View):

                   ┌─────────────────┐
                   │  Phishing Email │
                   │  sender@evil.com│
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │   Recipient     │
                   │ john@contoso.com│
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │  Malicious URL  │
                   │ https://evil.com│
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │  Malware File   │
                   │   payload.exe   │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │   Host Device   │
                   │  DESKTOP-123    │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ Lateral Movement│
                   │  RDP to SERVER01│
                   └─────────────────┘

Benefits:
- Visual attack chain (easy to understand)
- Click entities to see details (activities, properties)
- Identify pivot points (where to focus investigation)
- Export graph (for reporting, documentation)
```

**🎯 Exam Tip:**
- **Entity mapping**: Links query results to real-world entities (users, IPs, hosts, files)
- **Common entities**: Account, Host, IP, File, FileHash, Process, URL, Mailbox
- **Naming convention**: *CustomEntity suffix (AccountCustomEntity, IPCustomEntity, etc.)
- **Benefits**: Faster investigation, correlation, timeline, investigation graph
- **Multiple entities**: Map multiple entities per alert (full context)
- **Investigation graph**: Visual representation of attack chain (entity relationships)
- **Best practice**: Always map entities (critical for investigation efficiency)

---

## 14. ASIM Parsers

### 14.1 What is ASIM?

**Advanced Security Information Model (ASIM):**

```
ASIM (Advanced Security Information Model):
- Definition: Normalization schema for security data
- Purpose: Unified queries across different data sources
- Benefit: Write once, query anywhere (vendor-agnostic)

Problem Without ASIM:
❌ Different vendors, different schemas:
   - Palo Alto: SourceIP, DestIP
   - Cisco ASA: src, dst
   - Fortinet: srcip, dstip
   - Windows: IpAddress, DestinationIp

❌ Multiple queries needed:
   ```kql
   // Query 1: Palo Alto
   CommonSecurityLog | where DeviceVendor == "Palo Alto"
   | where SourceIP == "203.0.113.50"
   
   // Query 2: Cisco ASA
   CommonSecurityLog | where DeviceVendor == "Cisco"
   | where src == "203.0.113.50"
   
   // Query 3: Fortinet
   CommonSecurityLog | where DeviceVendor == "Fortinet"
   | where srcip == "203.0.113.50"
   ```

Solution with ASIM:
✅ Unified schema:
   - All vendors: SrcIpAddr, DstIpAddr (standard fields)

✅ Single query:
   ```kql
   imNetworkSession  // ASIM Network Session parser
   | where SrcIpAddr == "203.0.113.50"
   // Works for Palo Alto, Cisco, Fortinet, Fortinet, Windows, etc.
   ```

ASIM Schemas (Types):

1️⃣ Network Session: Firewall, network device logs
2️⃣ Authentication: Sign-ins, logons, authentication events
3️⃣ Process Events: Process creation, termination
4️⃣ File Events: File creation, access, deletion, modification
5️⃣ Registry Events: Registry key/value changes
6️⃣ DNS: DNS queries and responses
7️⃣ Web Session: Web proxy, HTTP traffic
8️⃣ Email: Email messages, URLs, attachments
9️⃣ Audit Events: General audit trail events
```

### 14.2 ASIM Parsers

**What are ASIM Parsers?**

```
ASIM Parser:
- Definition: KQL function that maps vendor-specific fields to ASIM schema
- Type: Parameterized function (takes filters as parameters)
- Deployment: Pre-built (Content hub) or custom

Parser Naming Convention:
├─ Unified parser: im<Schema> (e.g., imNetworkSession)
│  └─ Queries ALL sources (all vendors) using ASIM schema
├─ Source-specific parser: vim<Schema>Source (e.g., vimNetworkSessionPaloAlto)
│  └─ Queries SINGLE source (specific vendor)
└─ Filtering parser: _Im<Schema> (e.g., _ImNetworkSession)
   └─ Internal use (don't use directly in queries)

Examples:

Unified Parsers (Use These):
├─ imAuthentication: All sign-in/logon events (Entra ID, Windows, Linux)
├─ imNetworkSession: All network connections (firewalls, NSG, etc.)
├─ imProcessCreate: All process creation (Windows, Linux, MDE)
├─ imFileEvent: All file events (Windows, Linux, MDE, SharePoint)
└─ imDns: All DNS queries (Windows, Linux, firewalls)

Source-Specific Parsers:
├─ vimAuthenticationSigninLogs: Entra ID only
├─ vimNetworkSessionPaloAlto: Palo Alto Networks only
├─ vimProcessCreateMicrosoftSysmon: Sysmon only
└─ vimFileEventMicrosoftDefenderForEndpoint: MDE only
```

### 14.3 Using ASIM Parsers

**Query Examples with ASIM:**

**Example 1: Network Session (Firewall Detection)**

```kql
// Without ASIM (vendor-specific):
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == "203.0.113.50"  // Palo Alto field name
| where DeviceAction == "deny"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort

// Problem: Only works for Palo Alto. Need separate queries for Cisco, Fortinet, etc.

// With ASIM (vendor-agnostic):
imNetworkSession  // Unified parser
| where SrcIpAddr == "203.0.113.50"  // ASIM standard field
| where EventResult == "Failure"      // ASIM standard field
| project TimeGenerated, SrcIpAddr, DstIpAddr, DstPortNumber

// Benefit: Works for ALL network devices (Palo Alto, Cisco, Fortinet, Azure NSG, etc.)
```

**Example 2: Authentication (Sign-in Detection)**

```kql
// Without ASIM (multiple tables):
// Query 1: Azure AD
SigninLogs
| where UserPrincipalName == "john@contoso.com"
| where ResultType != 0  // Failed

// Query 2: Windows
SecurityEvent
| where EventID == 4625  // Failed logon
| where TargetUserName == "john"

// Query 3: Linux
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "Failed password"

// Problem: 3 separate queries, different field names

// With ASIM (unified):
imAuthentication  // Unified parser
| where TargetUsername == "john@contoso.com"
| where EventResult == "Failure"
| project TimeGenerated, TargetUsername, SrcIpAddr, LogonType, EventResultDetails

// Benefit: Works for Entra ID, Windows, Linux, AWS, GCP, Okta, etc.
```

**Example 3: Process Creation (Malware Detection)**

```kql
// Without ASIM (multiple sources):
// Query 1: Windows (SecurityEvent)
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine contains "-enc"

// Query 2: MDE (DeviceProcessEvents)
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc"

// Query 3: Sysmon (Event)
Event
| where EventID == 1  // Process creation
| where EventData has "powershell.exe"

// Problem: 3 queries, different schemas

// With ASIM (unified):
imProcessCreate  // Unified parser
| where Process has "powershell.exe"
| where CommandLine contains "-enc"
| project TimeGenerated, Dvc, ActingProcessName, Process, CommandLine, User

// Benefit: Works for Windows (SecurityEvent, Sysmon), Linux, MDE, EDR tools
```

**Example 4: File Events (Ransomware Detection)**

```kql
// Without ASIM (multiple sources):
// Query 1: MDE
DeviceFileEvents
| where ActionType == "FileDeleted"
| where FolderPath startswith "C:\\Users"

// Query 2: Windows (SecurityEvent 4663)
SecurityEvent
| where EventID == 4663  // Object access
| where ObjectName startswith "C:\\Users"

// Query 3: Office 365
OfficeActivity
| where Operation == "FileDeleted"

// Problem: 3 queries, inconsistent field names

// With ASIM (unified):
imFileEvent  // Unified parser
| where EventType == "FileDeleted"
| where TargetFilePath startswith "C:\\Users"
| project TimeGenerated, Dvc, ActorUsername, TargetFileName, TargetFilePath

// Benefit: Works for Windows, Linux, MDE, SharePoint, OneDrive, file servers
```

### 14.4 ASIM Parser Parameters

**Filtering at Parser Level (Performance Optimization):**

```kql
// ASIM parsers support parameters (pre-filtering)

// Without parameters (inefficient):
imNetworkSession
| where SrcIpAddr == "203.0.113.50"
| where DstPortNumber == 443
| where TimeGenerated > ago(1d)

// Problem: Parser queries ALL network sessions, then filters (slow)

// With parameters (efficient):
imNetworkSession(
    starttime = ago(1d),              // Time filter (passed to parser)
    srcipaddr_has_any = dynamic(["203.0.113.50"]),  // IP filter
    dstportnumber = 443               // Port filter
  )

// Benefit: Parser only queries relevant data (faster, lower cost)

Supported Parameters:
├─ starttime / endtime: Time range filter
├─ srcipaddr_has_any: Source IP addresses (array)
├─ dstipaddr_has_any: Destination IP addresses
├─ dstportnumber: Destination port
├─ hostname_has_any: Hostnames (for authentication, process events)
├─ username_has_any: Usernames
└─ eventtype: Event type filter (e.g., "FileDeleted")

Performance Impact:
- Without parameters: Query 100 GB data, filter 99.9 GB (expensive!)
- With parameters: Query 0.1 GB data (99.9% reduction!)
```

### 14.5 Custom ASIM Parsers

**Creating Custom Parsers for Unsupported Sources:**

```kql
// Scenario: Custom firewall (not supported by built-in parsers)

// Step 1: Create function (saved query)
let vimNetworkSessionCustomFirewall = (
    starttime: datetime = datetime(null),
    endtime: datetime = datetime(null)
  ) {
    CustomFirewallLog_CL
    | where isempty(starttime) or TimeGenerated >= starttime
    | where isempty(endtime) or TimeGenerated <= endtime
    // Map vendor-specific fields to ASIM schema
    | extend 
        EventStartTime = TimeGenerated,
        EventProduct = "CustomFirewall",
        EventVendor = "Contoso",
        EventSchema = "NetworkSession",
        EventSchemaVersion = "0.2.6",
        SrcIpAddr = SourceIP_s,       // Map SourceIP_s → SrcIpAddr
        DstIpAddr = DestIP_s,          // Map DestIP_s → DstIpAddr
        SrcPortNumber = toint(SourcePort_d),
        DstPortNumber = toint(DestPort_d),
        NetworkProtocol = Protocol_s,
        EventResult = case(
            Action_s == "allow", "Success",
            Action_s == "deny", "Failure",
            "Unknown"
          )
    | project-away *_s, *_d  // Remove original fields
  };

// Step 2: Save as function
// Portal: Sentinel → Logs → Save → Function → vimNetworkSessionCustomFirewall

// Step 3: Use in queries
vimNetworkSessionCustomFirewall(starttime = ago(1d))
| where SrcIpAddr == "203.0.113.50"
| where EventResult == "Failure"

// Step 4: Include in unified parser (advanced)
// Modify imNetworkSession to call custom parser:
let imNetworkSession = () {
  union 
    vimNetworkSessionPaloAlto(),
    vimNetworkSessionCisco(),
    vimNetworkSessionCustomFirewall()  // Add custom parser
};
```

**ASIM Schema Reference (Key Fields):**

```
Common ASIM Fields (All Schemas):

Mandatory:
├─ TimeGenerated: Event timestamp
├─ EventProduct: Product name (Palo Alto, Cisco ASA, etc.)
├─ EventVendor: Vendor name (Palo Alto Networks, Cisco, etc.)
├─ EventSchema: Schema name (NetworkSession, Authentication, etc.)
└─ EventSchemaVersion: ASIM version (e.g., 0.2.6)

Recommended:
├─ EventStartTime: Event start time
├─ EventEndTime: Event end time (for sessions)
├─ EventResult: Success, Failure, Partial (normalized result)
├─ EventResultDetails: Detailed result (InvalidPassword, ConnectionTimeout)
├─ EventMessage: Original message (for forensics)
└─ EventSeverity: Informational, Low, Medium, High, Critical

Network Session Schema:
├─ SrcIpAddr: Source IP address
├─ SrcPortNumber: Source port
├─ SrcHostname: Source hostname
├─ DstIpAddr: Destination IP address
├─ DstPortNumber: Destination port
├─ DstHostname: Destination hostname
├─ NetworkProtocol: TCP, UDP, ICMP, etc.
├─ NetworkDirection: Inbound, Outbound, Local
└─ NetworkBytes: Total bytes transferred

Authentication Schema:
├─ TargetUsername: Target user (authenticated as)
├─ TargetUserId: Target user ID (SID, GUID)
├─ LogonType: Interactive, Network, RemoteInteractive, etc.
├─ TargetAppName: Target application (Office 365, AWS Console)
├─ SrcIpAddr: Source IP address (where sign-in from)
├─ SrcHostname: Source hostname
└─ EventResultDetails: InvalidPassword, AccountDisabled, MFARequired

Process Schema:
├─ Process: Process name (powershell.exe)
├─ ProcessId: Process ID (PID)
├─ CommandLine: Full command line
├─ ProcessParent: Parent process name
├─ ProcessParentId: Parent PID
├─ User: User who ran process
└─ ActingProcessName: Process that initiated (e.g., cmd.exe → powershell.exe)

File Schema:
├─ TargetFileName: File name
├─ TargetFilePath: Full file path
├─ TargetFileHashSha256: SHA256 hash
├─ ActorUsername: User who performed action
├─ EventType: FileCreated, FileDeleted, FileModified, FileRenamed
└─ SrcFilePath: Source path (for copy/move operations)
```

**🎯 Exam Tip:**
- **ASIM**: Advanced Security Information Model (normalization schema)
- **Purpose**: Write once, query anywhere (vendor-agnostic queries)
- **Unified parsers**: im<Schema> (e.g., imNetworkSession, imAuthentication, imProcessCreate)
- **Source-specific parsers**: vim<Schema>Source (e.g., vimNetworkSessionPaloAlto)
- **Benefits**: Vendor-agnostic, reusable queries, simplified analytics rules
- **Parameters**: starttime, srcipaddr_has_any, username_has_any (performance optimization)
- **Common schemas**: NetworkSession, Authentication, ProcessCreate, FileEvent, DNS
- **Best practice**: Use ASIM parsers in analytics rules (future-proof, vendor changes)
- **Exam scenario**: "Query logs from multiple vendors" → Use ASIM unified parser

---

## 15. Rule Tuning & Optimization

### 15.1 Why Tune Analytics Rules?

**The Alert Fatigue Problem:**

```
Problem: Too Many Alerts
├─ Average SOC: 10,000+ alerts per day
├─ True positive rate: 10-30% (70-90% false positives!)
├─ Analyst burnout: Alert fatigue, missed threats
└─ Business impact: Slow response, high cost

Rule Tuning Goals:
1. Reduce false positives (90% → 10%)
2. Increase true positive rate (10% → 80%+)
3. Improve alert quality (actionable, high-fidelity)
4. Reduce alert volume (10,000 → 1,000 per day)
5. Speed up investigation (clear, enriched alerts)

Tuning Process:
1. Monitor: Collect rule metrics (alert volume, TP rate)
2. Analyze: Identify noisy rules (high FP rate)
3. Tune: Adjust thresholds, add filters, enrich context
4. Test: Validate changes (does TP rate improve?)
5. Deploy: Roll out tuned rules
6. Repeat: Continuous improvement (quarterly reviews)
```

### 15.2 Tuning Techniques

**Technique 1: Threshold Adjustment**

```kql
// Problem: Too many alerts (threshold too low)

// Before tuning (noisy):
SecurityEvent
| where EventID == 4625  // Failed logon
| summarize FailedLogins = count() by Computer, Account, bin(TimeGenerated, 5m)
| where FailedLogins > 3  // ← Low threshold (alerts on 4 attempts)

// Result: 1,000 alerts/day (many legitimate, e.g., users mistyping password)

// After tuning (reduced noise):
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Computer, Account, bin(TimeGenerated, 5m)
| where FailedLogins > 10  // ← Higher threshold (alerts on 11+ attempts)

// Result: 100 alerts/day (80% true positives, actual brute force)

Threshold Tuning Guidelines:
├─ Too low: Many alerts, high FP rate (alert fatigue)
├─ Too high: Few alerts, may miss threats (false negatives)
├─ Goldilocks zone: Balance (80%+ TP rate, manageable volume)
└─ Find sweet spot: Analyze historical data, test thresholds
```

**Technique 2: Exclusions (Whitelist Known-Good)**

```kql
// Problem: Alerts on legitimate activities

// Before tuning (includes noise):
SecurityEvent
| where EventID == 4688  // Process creation
| where Process has "powershell.exe"
| where CommandLine contains "-enc"  // Encoded command

// Result: 500 alerts/day (includes legitimate automation scripts)

// After tuning (exclude known-good):
let LegitimateScripts = dynamic([
    "C:\\Scripts\\BackupJob.ps1",
    "C:\\Admin\\MonitoringScript.ps1"
  ]);  // Whitelist legitimate scripts

SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine contains "-enc"
| where not(CommandLine has_any (LegitimateScripts))  // ← Exclude whitelist
| where not(Account has_any ("svc-backup", "svc-monitoring"))  // Exclude service accounts

// Result: 50 alerts/day (90% true positives, actual threats)

Exclusion Best Practices:
✅ Document: Why excluded? (business justification)
✅ Review: Quarterly review (is exclusion still valid?)
✅ Limit: Don't over-exclude (may hide threats)
⚠️ Risk: Attackers may abuse whitelisted paths/accounts
```

**Technique 3: Contextual Filters (Enrich Logic)**

```kql
// Problem: Lack of context (benign activities flagged)

// Before tuning (missing context):
SigninLogs
| where Location != "Office"  // Alert on non-office sign-ins

// Result: 5,000 alerts/day (includes traveling employees, WFH)

// After tuning (add context):
// Step 1: Define VIP users (context 1)
let VIPUsers = dynamic([
    "ceo@contoso.com",
    "cfo@contoso.com"
  ]);

// Step 2: Get malicious IPs (context 2)
let MaliciousIPs = ThreatIntelIndicators
| where Active == true
| where NetworkIP != ""
| distinct NetworkIP;

// Step 3: Detect with context
SigninLogs
| where Location != "Office"
| where UserPrincipalName in (VIPUsers)  // ← Context 1: VIP only
   or IPAddress in (MaliciousIPs)        // ← Context 2: Known malicious IP
   or RiskLevelDuringSignIn == "high"    // ← Context 3: Identity Protection risk
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskLevelDuringSignIn

// Result: 50 alerts/day (95% true positives, actual threats)

Contextual Filters:
├─ User context: VIP, admin, service accounts
├─ Time context: After hours, weekends, holidays
├─ Location context: Unusual countries, known malicious IPs
├─ Risk context: Identity Protection, UEBA scores
└─ Threat intel: IoC matches, known attack patterns
```

**Technique 4: Alert Suppression**

```
Suppression Use Cases:

1️⃣ Single Event, Multiple Alerts
   Problem: Same issue generates multiple alerts
   Example: Brute force attack (10 alerts in 5 minutes)
   Solution: Suppress for 24 hours after first alert

   Configuration:
   Sentinel → Analytics → Edit Rule → Incident settings → Suppression
   ├─ Enable: Stop creating alerts if rule query generates results
   ├─ Suppress for: 24 hours
   └─ Result: 1 alert per 24 hours (not 10 per hour)

2️⃣ Known Issue, Awaiting Fix
   Problem: Infrastructure issue (cannot fix immediately)
   Example: Legacy app generates "failed logon" every 5 minutes
   Solution: Suppress rule temporarily (until app fixed)

   Configuration:
   Sentinel → Analytics → Disable rule (temporarily)
   ├─ Add note: "Disabled due to known issue (Ticket #12345)"
   ├─ Set reminder: Re-enable after fix deployed
   └─ Alternative: Add exclusion filter (exclude legacy app)

Best Practices:
✅ Document: Why suppressed? (ticket number, issue description)
✅ Time-bound: Set re-evaluation date (don't suppress forever)
✅ Review: Monthly suppression review (is issue resolved?)
⚠️ Risk: Don't suppress critical alerts (may hide real threats)
```

**Technique 5: Dynamic Severity (Risk-Based Alerting)**

```kql
// Problem: All alerts same severity (cannot prioritize)

// Before tuning (static severity):
SecurityEvent
| where EventID == 4625  // Failed logon
| summarize FailedLogins = count() by Account, Computer
| where FailedLogins > 10

// Rule severity: High (always) - no prioritization

// After tuning (dynamic severity):
let VIPUsers = dynamic(["admin", "ceo", "cfo"]);
let ServiceAccounts = dynamic(["svc-backup", "svc-app"]);

SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedLogins > 10
| extend 
    Severity = case(
        Account has_any (VIPUsers), "Critical",      // VIP account: Critical
        FailedLogins > 100, "Critical",              // 100+ attempts: Critical
        FailedLogins > 50, "High",                   // 50-100 attempts: High
        Account has_any (ServiceAccounts), "Low",    // Service account: Low
        "Medium"                                     // Default: Medium
      ),
    Priority = case(
        Account has_any (VIPUsers), 1,               // VIP: Top priority
        FailedLogins > 100, 1,
        FailedLogins > 50, 2,
        Account has_any (ServiceAccounts), 99,       // Service account: Low priority
        3                                            // Default: Normal priority
      )
| project TimeGenerated, Account, Computer, FailedLogins, Severity, Priority

// Result: Analysts prioritize Critical/High first (VIPs, high-volume attacks)

Note: Dynamic severity requires custom field (extend). Sentinel severity is static (set in rule).
Workaround: Use incident assignment rules (auto-assign based on custom field).
```

### 15.3 Rule Performance Optimization

**Query Performance Tips:**

```
Slow Query Problems:
❌ Query takes >60 seconds (timeout risk)
❌ High resource usage (slows workspace for others)
❌ Missed alerts (query doesn't complete before next run)

Optimization Techniques:

1️⃣ Filter Early (Most Important!)
   ❌ Bad:
   SecurityEvent
   | project TimeGenerated, Computer, Account, EventID
   | where TimeGenerated > ago(1h)
   | where EventID == 4625

   ✅ Good:
   SecurityEvent
   | where TimeGenerated > ago(1h)  // ← Filter FIRST (reduce dataset)
   | where EventID == 4625           // ← Filter SECOND
   | project TimeGenerated, Computer, Account, EventID

2️⃣ Use summarize Instead of distinct
   ❌ Slow:
   SecurityEvent
   | where EventID == 4625
   | distinct Computer

   ✅ Fast:
   SecurityEvent
   | where EventID == 4625
   | summarize by Computer

3️⃣ Limit join Complexity
   ❌ Slow:
   Table1
   | join kind=inner (Table2) on Key1, Key2, Key3  // Multiple keys

   ✅ Fast:
   Table1
   | join kind=inner (Table2) on Key1  // Single key

4️⃣ Avoid scanning Entire Table
   ❌ Slow:
   SecurityEvent  // No time filter (scans all historical data!)
   | where EventID == 4625

   ✅ Fast:
   SecurityEvent
   | where TimeGenerated > ago(1h)  // ← Always add time filter!
   | where EventID == 4625

5️⃣ Use project Early
   ❌ Slow:
   SecurityEvent
   | where TimeGenerated > ago(1h)
   | where EventID == 4625
   | join kind=inner (Table2) on Computer  // Join on full table (100 columns)

   ✅ Fast:
   SecurityEvent
   | where TimeGenerated > ago(1h)
   | where EventID == 4625
   | project TimeGenerated, Computer, Account  // ← Reduce columns BEFORE join
   | join kind=inner (Table2) on Computer

6️⃣ Monitor Query Performance
   Use query_properties():
   
   SecurityEvent
   | where TimeGenerated > ago(1h)
   | where EventID == 4625
   | summarize count()
   | extend QueryStats = query_properties()

   Review:
   - TotalCPU: CPU time (optimize if >10 seconds)
   - DataScanned: Data volume (optimize if >10 GB)
   - Duration: Query time (optimize if >30 seconds)
```

### 15.4 Rule Maintenance Checklist

**Ongoing Rule Management:**

```
Monthly Tasks:
✅ Review alert volume (dashboard: Usage workbook)
✅ Calculate true positive rate (TP / Total alerts)
✅ Identify top 10 noisy rules (high volume, low TP rate)
✅ Review suppressed rules (can re-enable?)
✅ Check for new Content hub solutions (updated rules)

Quarterly Tasks:
✅ Deep dive: Top 5 noisiest rules (tune thresholds, add filters)
✅ Review exclusions: Still valid? (business justification)
✅ Performance check: Slow queries? (optimize)
✅ Coverage analysis: Any gaps? (new threats, TTPs)
✅ Benchmark: Compare to industry (MITRE ATT&CK coverage)

Annual Tasks:
✅ Complete rule audit: Every rule reviewed (still relevant?)
✅ Decommission: Obsolete rules (old threats, deprecated sources)
✅ Alignment: Business priorities (new VIPs, new apps, new threats)
✅ Training: Analyst training (new rules, updated TTPs)

Metrics to Track:
├─ Alert volume: Total alerts per day/week/month
├─ True positive rate: TP / (TP + FP) × 100%
├─ Mean Time to Triage (MTTT): Time from alert to analyst review
├─ Mean Time to Respond (MTTR): Time from alert to remediation
├─ Rule coverage: % of MITRE ATT&CK techniques covered
└─ Analyst feedback: Rule quality scores (useful? actionable?)

Target KPIs:
├─ True positive rate: 80%+ (good), 90%+ (excellent)
├─ Alert volume: <500 per analyst per day (manageable)
├─ MTTT: <15 minutes (fast triage)
├─ MTTR: <1 hour (critical), <4 hours (high), <24 hours (medium)
└─ MITRE ATT&CK coverage: 70%+ techniques (comprehensive)
```

**🎯 Exam Tip:**
- **Tuning goals**: Reduce false positives (90% → 10%), increase true positive rate
- **Techniques**: Threshold adjustment, exclusions (whitelist), contextual filters, suppression, dynamic severity
- **Performance**: Filter early (where clauses first), use summarize (not distinct), limit join complexity
- **Maintenance**: Monthly reviews (alert volume, TP rate), quarterly deep dives (top noisy rules)
- **Metrics**: True positive rate (target 80%+), MTTT (<15 min), MTTR (<1 hour critical)
- **Best practice**: Continuous improvement (tune, test, deploy, repeat)
- **Exam scenario**: "Too many false positives" → Apply tuning techniques (threshold, exclusions, context)

---

**🎉 END OF MODULE 5 PART 3! 🎉**

You've mastered **Detection Engineering**:
- ✅ Analytics Rules Overview (5 types, components, deployment methods)
- ✅ Scheduled Query Rules (KQL queries, real-world examples, advanced techniques, behavioral baselining)
- ✅ Near-Real-Time (NRT) Rules (1-min detection, limitations, critical use cases, 50 rule limit)
- ✅ Anomaly Detection Rules (ML-based, 30-day learning, behavioral analysis, no KQL)
- ✅ Fusion Rules (multi-stage attacks, cross-product correlation, 80%+ true positive rate)
- ✅ Entity Mapping (users, IPs, hosts, files, investigation graph, entity relationships)
- ✅ ASIM Parsers (normalization, vendor-agnostic queries, unified schemas, performance parameters)
- ✅ Rule Tuning & Optimization (threshold adjustment, exclusions, contextual filters, performance optimization, maintenance)

**Progress: Module 5 Part 3 COMPLETE! (~35,000 words)**

**Module 5 Overall Progress:**
- Part 1: ✅ Complete (Sections 1-4) - Foundation, Architecture, Configuration, Data Connectors
- Part 2: ✅ Complete (Sections 4.3-8) - DCR, Custom Logs, Threat Intelligence, Cost Optimization
- Part 3: ✅ Complete (Sections 9-15) - Analytics Rules, Detection, Entity Mapping, ASIM, Tuning
- **~60% of Module 5 Complete!**

**Coming in Parts 4-6:**
- **Part 4**: Incidents & Automation (triage, investigation, playbooks, SOAR)
- **Part 5**: Threat Hunting & Visualization (hunting queries, bookmarks, livestream, notebooks, workbooks, UEBA)
- **Part 6**: Exam Mastery (20+ practice questions, KQL deep dive, exam strategies)

**Continue to Part 4 (Incidents & Automation)?** This is where SOC analysts spend most of their time! 🚀🔥
