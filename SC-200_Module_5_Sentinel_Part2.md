# SC-200 Study Notes - Module 5: Microsoft Sentinel (Part 2)
## 🛡️ Data Collection, Threat Intelligence & Cost Optimization

**Continuation of Part 1** - Sections 4.3-8
**Last Updated:** October 2025
**Based on:** Official SC-200 Study Guide + Latest Sentinel Updates

---

## 4.3 Agent-Based Connectors

### Windows Security Events via AMA

**Azure Monitor Agent (AMA) - Modern Agent:**

```
What: Next-generation data collection agent (replaces Log Analytics Agent)

AMA vs Legacy Agent (MMA):

┌────────────────────────────────────────────────────────┐
│ Feature          | Legacy Agent (MMA) | AMA           │
├────────────────────────────────────────────────────────┤
│ Status           | Deprecated (2024)  | Current (GA)  │
│ OS Support       | Windows, Linux     | Windows, Linux│
│ Configuration    | Workspace-based    | DCR-based     │
│ Filtering        | Limited            | Advanced      │
│ Multi-homing     | Yes                | Yes           │
│ Performance      | Moderate           | Better        │
│ Management       | Complex            | Simplified    │
└────────────────────────────────────────────────────────┘

⚠️ Legacy Agent (MMA/OMS) deprecated August 2024
   → Migrate to AMA before end of support!
```

**Deploying AMA for Windows Security Events:**

```
Configuration Steps:

Step 1: Create Data Collection Rule (DCR)
─────────────────────────────────────────
Azure Portal → Monitor → Data Collection Rules → Create

DCR Configuration:
├─ Rule name: DCR-WindowsSecurityEvents-Prod
├─ Subscription: Select subscription
├─ Resource group: rg-sentinel-prod
├─ Region: Same as Sentinel workspace
├─ Platform: Windows
└─ Data source: Windows Event Logs

Event Sets (Pre-defined Collections):
┌──────────────────────────────────────────────────┐
│ Set         | Events/Day | Use Case              │
├──────────────────────────────────────────────────┤
│ All Events  | ~5,000+    | Forensics, compliance │
│ Common      | ~300       | Recommended (balance) │
│ Minimal     | ~50        | Basic monitoring      │
│ Custom      | Varies     | Specific Event IDs    │
└──────────────────────────────────────────────────┘

Common Set (Recommended):
- Includes: Logins, process creation, privilege use, firewall changes
- Excludes: Noise (routine events like Group Policy refresh)
- Size: ~300 events/day per machine

Custom XPath Queries (Advanced Filtering):
Example: Only Security Event ID 4625 (Failed Logons)
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4625)]]
    </Select>
  </Query>
</QueryList>

Step 2: Assign DCR to Resources
─────────────────────────────────────────
DCR → Resources → Add

Assignment Options:
├─ Individual VMs: Select specific machines
├─ Resource Group: All VMs in RG
├─ Subscription: All VMs in subscription
└─ Azure Policy: Auto-assign to VMs matching criteria (recommended)

Azure Policy Assignment (Recommended):
Policy: "Configure Windows machines to run Azure Monitor Agent"
- Scope: Subscription or Resource Group
- Effect: DeployIfNotExists (auto-installs AMA)
- Remediation: Auto-remediate existing VMs

Step 3: Verify Data Collection
─────────────────────────────────────────
Wait: 5-10 minutes for first events

Query:
SecurityEvent
| where TimeGenerated > ago(1h)
| where Computer == "SERVER01"
| take 10

Expected: Security events appearing in SecurityEvent table

Step 4: Monitor Collection Health
─────────────────────────────────────────
Sentinel → Health → Data connectors

Check:
✅ AMA installed on targets
✅ DCR assigned correctly
✅ Events flowing (ingestion rate)
❌ Errors: Missing permissions, agent offline, DCR misconfigured
```

**Key Security Event IDs (SC-200 Exam Focus):**

```
Critical Windows Security Events:

Account Logon Events:
├─ 4624: Successful logon
├─ 4625: Failed logon (brute force indicator)
├─ 4634: Logoff
├─ 4648: Logon with explicit credentials (runas)
└─ 4672: Special privileges assigned (admin logon)

Account Management:
├─ 4720: User account created
├─ 4722: User account enabled
├─ 4723: Password change attempt
├─ 4724: Password reset attempt
├─ 4725: User account disabled
├─ 4726: User account deleted
├─ 4728: Member added to security-enabled global group
├─ 4732: Member added to security-enabled local group
└─ 4756: Member added to security-enabled universal group

Privilege Use:
├─ 4672: Special privileges assigned to new logon
├─ 4673: Privileged service called
└─ 4674: Operation attempted on privileged object

Process Tracking:
├─ 4688: New process created (PowerShell, cmd, etc.)
└─ 4689: Process exited

Object Access:
├─ 4663: Attempt to access object (file, registry)
├─ 4656: Handle to object requested
└─ 4660: Object deleted

Policy Change:
├─ 4719: System audit policy changed
├─ 4739: Domain policy changed
└─ 4670: Permissions on object changed

System Events:
├─ 4616: System time changed
├─ 4697: Service installed
├─ 1102: Audit log cleared (cover tracks)
└─ 7045: Service installed (malware persistence)

Detection Use Cases:
├─ Brute force: Multiple 4625 events (>10 in 5 min)
├─ Privilege escalation: 4728/4732 (added to admin group)
├─ Lateral movement: 4648 (explicit credential use)
├─ Persistence: 4697/7045 (service installed)
├─ Anti-forensics: 1102 (log cleared)
└─ Suspicious processes: 4688 (PowerShell, wmic, etc.)
```

### Linux Syslog

**Collecting Linux Syslog:**

```
Syslog Connector Architecture:

Linux Machines → rsyslog/syslog-ng → Log Analytics workspace → Sentinel

Configuration Steps:

Step 1: Deploy AMA on Linux
─────────────────────────────────────────
Install via:
- Azure portal (VM extension)
- Azure Policy (auto-deploy)
- CLI: az vm extension set

Step 2: Create DCR for Syslog
─────────────────────────────────────────
Azure Portal → Monitor → Data Collection Rules → Create

Configuration:
├─ Platform: Linux
├─ Data source: Linux Syslog
├─ Facilities: Select log sources
│  ├─ auth (authentication)
│  ├─ authpriv (SSH, sudo)
│  ├─ syslog (general system)
│  ├─ daemon (background services)
│  ├─ kern (kernel messages)
│  └─ cron (scheduled tasks)
│
└─ Log levels: Select severity
   ├─ Emergency (0) - system unusable
   ├─ Alert (1) - immediate action needed
   ├─ Critical (2) - critical conditions
   ├─ Error (3) - error conditions
   ├─ Warning (4) - warning conditions
   ├─ Notice (5) - normal but significant
   ├─ Info (6) - informational
   └─ Debug (7) - debug messages

Recommended Configuration:
Facility: authpriv (SSH/sudo) → Log level: Info
Facility: syslog (general) → Log level: Warning
Facility: daemon (services) → Log level: Error

Step 3: Configure rsyslog (on Linux machine)
─────────────────────────────────────────
File: /etc/rsyslog.d/95-omsagent.conf

*.info;mail.none;authpriv.none;cron.none @127.0.0.1:25224

Restart rsyslog:
sudo systemctl restart rsyslog

Step 4: Verify Collection
─────────────────────────────────────────
Query:
Syslog
| where TimeGenerated > ago(1h)
| where Computer == "ubuntu-vm-01"
| take 10

Table: Syslog
Columns:
├─ Computer: Hostname
├─ Facility: Log source (authpriv, syslog, etc.)
├─ SeverityLevel: Info, Warning, Error, etc.
├─ SyslogMessage: Log message text
└─ ProcessName: Process that generated log
```

**Common Syslog Detection Use Cases:**

```
SSH Brute Force Detection:
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "Failed password"
| summarize FailedLogins = count() by Computer, bin(TimeGenerated, 5m)
| where FailedLogins > 10

Privilege Escalation (sudo):
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "sudo"
| where SyslogMessage contains "COMMAND"

Service Failures:
Syslog
| where Facility == "daemon"
| where SeverityLevel == "err"
| where SyslogMessage contains "failed"

Kernel Panics:
Syslog
| where Facility == "kern"
| where SeverityLevel == "emerg" or SeverityLevel == "crit"
```

### 4.4 Syslog / CEF Connectors

**Common Event Format (CEF) for Network Devices:**

```
CEF Architecture:

Firewall/IDS/IPS → Syslog (CEF format) → Linux Forwarder → Sentinel

Why CEF?
- Standardized format (ArcSight format)
- Supported by 100+ security vendors
- Easy parsing (structured fields)

CEF Message Format:
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Example:
CEF:0|Palo Alto Networks|PAN-OS|8.0|TRAFFIC|end|3|
rt=Jan 01 2025 12:00:00 src=10.0.0.5 dst=203.0.113.50 spt=54321 dpt=443
```

**Deploying CEF Collector:**

```
Step 1: Deploy Linux VM (CEF Forwarder)
─────────────────────────────────────────
Recommended Specs:
├─ OS: Ubuntu 18.04/20.04 or RHEL 7/8
├─ CPU: 2 vCPUs minimum (4 recommended)
├─ RAM: 4 GB minimum (8 GB recommended)
├─ Disk: 50 GB
└─ Network: Open ports 514 (TCP/UDP), 25226

Note: Can handle 500+ devices per forwarder

Step 2: Install CEF Collector Script
─────────────────────────────────────────
Run as root on Linux VM:

wget -O cef_installer.py \
https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_installer.py

sudo python cef_installer.py <WorkspaceID> <WorkspaceKey>

Script installs:
- Rsyslog (syslog daemon)
- AMA agent (sends logs to Sentinel)
- CEF parser (parses CEF format)

Step 3: Configure Firewall to Send CEF Logs
─────────────────────────────────────────
Example: Palo Alto Firewall

1. Go to: Device → Server Profiles → Syslog
2. Create syslog profile:
   - Name: Sentinel-CEF
   - Server: <Linux_Forwarder_IP>:514
   - Transport: TCP
   - Format: BSD
   - Facility: LOG_LOCAL4

3. Go to: Objects → Log Forwarding
4. Create profile:
   - Name: Forward-to-Sentinel
   - Log types: Traffic, Threat, Wildfire
   - Syslog profile: Sentinel-CEF

5. Apply to Security Policies
   - Select policies
   - Actions → Log Forwarding: Forward-to-Sentinel

Step 4: Verify CEF Collection
─────────────────────────────────────────
Wait: 10-20 minutes for first logs

Query:
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Palo Alto Networks"
| take 10

Table: CommonSecurityLog (CEF parsed)
Key Columns:
├─ DeviceVendor: Vendor name (Palo Alto, Cisco, etc.)
├─ DeviceProduct: Product name (PAN-OS, ASA, etc.)
├─ DeviceAction: Action taken (allow, deny, alert)
├─ SourceIP / DestinationIP: IPs
├─ SourcePort / DestinationPort: Ports
├─ Protocol: TCP, UDP, ICMP
├─ Severity: 0-10 (CEF severity scale)
└─ Message: Original CEF message
```

**Supported CEF Vendors (SC-200 Focus):**

```
Firewalls:
├─ Palo Alto Networks (PAN-OS)
├─ Cisco ASA, Firepower
├─ Fortinet FortiGate
├─ Check Point (via Log Exporter)
└─ pfSense / OPNsense

IDS/IPS:
├─ Cisco Firepower
├─ Fortinet FortiGate IPS
├─ Snort
└─ Suricata

WAF (Web Application Firewall):
├─ F5 BIG-IP ASM
├─ Imperva SecureSphere
└─ Barracuda WAF

Network Security:
├─ Zscaler (Internet Access, Private Access)
├─ Cisco Umbrella (DNS security)
└─ Cisco Meraki

Endpoint Security:
├─ Symantec Endpoint Protection
├─ Trend Micro Deep Security
└─ CrowdStrike (via Syslog)

Full list: 100+ vendors in Sentinel documentation
```

**🎯 Exam Tip:**
- **AMA** = Modern agent (replaced MMA), DCR-based configuration
- **DCR** (Data Collection Rule) = Defines what data to collect, where to send
- **Windows Security Events**: Use "Common" set (balanced), know key Event IDs (4624, 4625, 4688, 1102)
- **Linux Syslog**: Facilities (authpriv, syslog, daemon), severity levels
- **CEF**: Common Event Format (ArcSight), requires Linux forwarder VM
- **CEF vendors**: Palo Alto, Cisco, Fortinet, Check Point, Zscaler
- **Tables**: SecurityEvent (Windows), Syslog (Linux), CommonSecurityLog (CEF)

---

## 5. Data Collection Rules (DCR)

### 5.1 DCR Overview

**What are Data Collection Rules?**

```
Data Collection Rule (DCR):
- Defines: WHAT data to collect, WHERE to send it, HOW to transform it
- Scope: Can apply to multiple resources (VMs, resource groups, subscriptions)
- Format: ARM template (Infrastructure as Code)
- Benefits: Centralized management, version control, consistency

DCR vs Workspace Configuration:
┌────────────────────────────────────────────────────────┐
│ Feature          | Workspace Config | DCR              │
├────────────────────────────────────────────────────────┤
│ Agent            | MMA (legacy)     | AMA (modern)     │
│ Configuration    | Per-workspace    | Reusable         │
│ Filtering        | Limited          | Advanced (XPath) │
│ Transformation   | No               | Yes (KQL)        │
│ Deployment       | Manual           | ARM, Policy      │
│ Multi-workspace  | No               | Yes              │
└────────────────────────────────────────────────────────┘

🎯 Exam: Always use DCR (not workspace config) for AMA scenarios
```

### 5.2 DCR Components

**DCR Structure:**

```json
{
  "name": "DCR-WindowsSecurityEvents",
  "location": "eastus",
  "properties": {
    "dataSources": {
      "windowsEventLogs": [
        {
          "streams": ["Microsoft-SecurityEvent"],
          "xPathQueries": [
            "Security!*[System[(EventID=4624 or EventID=4625)]]"
          ],
          "name": "eventLogsDataSource"
        }
      ]
    },
    "destinations": {
      "logAnalytics": [
        {
          "workspaceResourceId": "/subscriptions/.../workspaces/sentinel-prod",
          "name": "sentinelWorkspace"
        }
      ]
    },
    "dataFlows": [
      {
        "streams": ["Microsoft-SecurityEvent"],
        "destinations": ["sentinelWorkspace"]
      }
    ]
  }
}
```

**DCR Components Explained:**

```
1️⃣ Data Sources (What to Collect)
   ├─ Windows Event Logs: Security, Application, System
   │  └─ XPath queries: Filter specific Event IDs
   ├─ Linux Syslog: Facilities and severity levels
   ├─ Performance Counters: CPU, memory, disk, network
   └─ Custom Logs: IIS logs, application logs

2️⃣ Destinations (Where to Send)
   ├─ Log Analytics Workspace (primary)
   ├─ Azure Monitor Metrics (for performance data)
   └─ Azure Event Hubs (for streaming to SIEM)

3️⃣ Data Flows (Routing)
   ├─ Maps: Data source → Destination
   ├─ Transformation: Apply KQL transformations (filter, enrich)
   └─ Multiple flows: One source → multiple destinations

4️⃣ Transformations (🆕 Advanced Feature)
   ├─ KQL-based: Filter, parse, enrich data
   ├─ Example: Filter out noisy events before ingestion
   ├─ Benefit: Reduce ingestion costs (send only relevant data)
   └─ Syntax: KQL query in DCR definition

Example Transformation (Filter noisy Event ID 5158):
source
| where EventID != 5158  // Exclude network connection events
| where Computer !contains "test"  // Exclude test machines
```

### 5.3 Advanced DCR Scenarios

**Scenario 1: Multi-Workspace Data Collection**

```
Use Case: Send same data to multiple workspaces (prod + archive)

DCR Configuration:
"destinations": {
  "logAnalytics": [
    {
      "workspaceResourceId": "/subscriptions/.../workspaces/sentinel-prod",
      "name": "prodWorkspace"
    },
    {
      "workspaceResourceId": "/subscriptions/.../workspaces/sentinel-archive",
      "name": "archiveWorkspace"
    }
  ]
},
"dataFlows": [
  {
    "streams": ["Microsoft-SecurityEvent"],
    "destinations": ["prodWorkspace", "archiveWorkspace"]
  }
]

Benefit:
- Prod workspace: 90-day retention, active investigations
- Archive workspace: 7-year retention, compliance
```

**Scenario 2: Filtering Data at Source (Cost Optimization)**

```
Problem: Too many noisy events (Event ID 5156 - Windows Filtering Platform)
Solution: Filter at DCR (don't ingest unnecessary data)

XPath Query (Filter at Source):
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID != 5156)]]
    </Select>
  </Query>
</QueryList>

Alternative: KQL Transformation in DCR
source
| where EventID != 5156
| where EventID != 5158  // Also filter network connections
| where EventID != 5157  // Also filter WFP filter

Cost Savings:
- Before: 10 GB/day (including noisy events)
- After: 3 GB/day (filtered)
- Savings: $5,138/month at $2.46/GB (70% reduction!)
```

**Scenario 3: Enrichment at Collection (Advanced)**

```
Use Case: Enrich events with custom data (business context)

Example: Add "Department" field to events based on computer name

KQL Transformation:
source
| extend Department = case(
    Computer startswith "HR-", "Human Resources",
    Computer startswith "FIN-", "Finance",
    Computer startswith "IT-", "IT",
    Computer startswith "SALES-", "Sales",
    "Unknown"
  )
| extend Region = case(
    Computer endswith "-US", "United States",
    Computer endswith "-EU", "Europe",
    Computer endswith "-APAC", "Asia-Pacific",
    "Unknown"
  )

Benefit:
- Enrichment at ingestion (no query-time overhead)
- Enables filtering by Department/Region in analytics rules
- Better for compliance reporting (group by department)
```

**🎯 Exam Tip:**
- **DCR** = Data Collection Rule (AMA configuration, ARM template)
- **Components**: Data sources (what), Destinations (where), Data flows (routing), Transformations (how)
- **Filtering**: XPath queries (Windows Event Logs), KQL transformations (all data types)
- **Multi-workspace**: Send same data to multiple workspaces
- **Cost optimization**: Filter noisy data at source (before ingestion)
- **Advanced**: KQL transformations for enrichment, filtering, parsing

---

## 6. Custom Log Tables

### 6.1 Custom Logs Overview

**When to Use Custom Logs:**

```
Scenarios:
✅ Application logs (not supported by built-in connectors)
✅ Custom security tools (proprietary format)
✅ Legacy systems (no standard syslog/CEF support)
✅ IoT devices (custom telemetry)
✅ Third-party SaaS (via REST API)

Custom Log Sources:
├─ Text files: IIS logs, Apache logs, application logs
├─ JSON files: Structured application logs
├─ CSV files: Custom exports
├─ REST API: Any system with API (via Logic Apps)
└─ Streaming: Event Hubs, Kafka
```

### 6.2 HTTP Data Collector API

**Ingesting Custom Logs via REST API:**

```
API Endpoint:
POST https://<WorkspaceID>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01

Headers:
- Content-Type: application/json
- Log-Type: MyCustomLog (table name without _CL suffix)
- Authorization: SharedKey <WorkspaceID>:<Signature>
- x-ms-date: RFC1123 date
- time-generated-field: Timestamp field name (optional)

Body (JSON):
[
  {
    "Timestamp": "2025-10-23T10:30:00Z",
    "Computer": "WEB-01",
    "EventID": 1001,
    "Message": "Application started successfully",
    "User": "john@contoso.com"
  },
  {
    "Timestamp": "2025-10-23T10:31:00Z",
    "Computer": "WEB-01",
    "EventID": 1002,
    "Message": "User authenticated",
    "User": "jane@contoso.com"
  }
]

Response:
200 OK (ingestion successful)

Custom Table Created:
└─ MyCustomLog_CL (note _CL suffix automatically added)

Columns:
├─ TimeGenerated: Ingestion time (auto-added)
├─ Timestamp: Custom timestamp (from JSON, if specified)
├─ Computer_s: String field
├─ EventID_d: Double (numeric field)
├─ Message_s: String field
└─ User_s: String field

Note: Suffix conventions:
- _s: String
- _d: Double (number)
- _b: Boolean
- _g: GUID
- _t: DateTime
```

**Sample PowerShell Script (HTTP Data Collector):**

```powershell
# Parameters
$WorkspaceId = "12345678-1234-1234-1234-123456789012"
$WorkspaceKey = "base64encodedkey=="
$LogType = "MyCustomLog"

# Build JSON payload
$json = @"
[
  {
    "Timestamp": "$(Get-Date -Format o)",
    "Computer": "$env:COMPUTERNAME",
    "EventID": 1001,
    "Message": "PowerShell event logged",
    "User": "$env:USERNAME"
  }
]
"@

# Build authorization signature
$method = "POST"
$contentType = "application/json"
$resource = "/api/logs"
$rfc1123date = [DateTime]::UtcNow.ToString("r")
$contentLength = $json.Length

$xHeaders = "x-ms-date:" + $rfc1123date
$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
$keyBytes = [Convert]::FromBase64String($WorkspaceKey)
$sha256 = New-Object System.Security.Cryptography.HMACSHA256
$sha256.Key = $keyBytes
$calculatedHash = $sha256.ComputeHash($bytesToHash)
$encodedHash = [Convert]::ToBase64String($calculatedHash)
$authorization = 'SharedKey {0}:{1}' -f $WorkspaceId,$encodedHash

# Build headers
$headers = @{
    "Authorization" = $authorization
    "Log-Type" = $LogType
    "x-ms-date" = $rfc1123date
}

# Send to Sentinel
$uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
Invoke-RestMethod -Uri $uri -Method Post -ContentType $contentType -Headers $headers -Body $json

Write-Host "Custom log sent to Sentinel successfully!"
```

### 6.3 Custom Table Schema

**Designing Custom Tables:**

```
Best Practices:

1️⃣ Table Naming
   ├─ Use descriptive names: AppName_EventType_CL
   ├─ Examples: WebApp_Login_CL, Firewall_Deny_CL
   ├─ Avoid: Generic names (CustomLog_CL, Data_CL)
   └─ Note: _CL suffix automatically added

2️⃣ Field Naming
   ├─ Use consistent naming: PascalCase or snake_case
   ├─ Good: UserPrincipalName, source_ip_address
   ├─ Avoid: usr, src, data1 (not descriptive)
   └─ Include: Timestamp, Computer, User (standard fields)

3️⃣ Data Types
   ├─ Use appropriate types: String, Double, Boolean, DateTime
   ├─ Sentinel auto-detects: Based on first values ingested
   ├─ Problem: If first value is "123", detected as Double (not String!)
   └─ Solution: Send sample with all data types first (schema definition)

4️⃣ Schema Evolution
   ├─ Adding fields: Automatic (new fields added on ingestion)
   ├─ Changing types: Not supported (create new table)
   └─ Deleting fields: Not needed (just stop sending)

Example Schema:
Table: CustomApp_Security_CL
├─ TimeGenerated: DateTime (auto, ingestion time)
├─ Timestamp: DateTime (event time, custom)
├─ Computer: String (hostname)
├─ AppName: String (application name)
├─ EventID: Double (numeric event ID)
├─ EventType: String (Login, Logout, Access, etc.)
├─ User: String (UPN or username)
├─ SourceIP: String (IP address)
├─ Result: String (Success, Failure)
├─ Message: String (detailed message)
└─ Severity: Double (1-10 severity scale)
```

### 6.4 Parsing Custom Logs

**KQL Parsing Examples:**

**Example 1: Parse IIS Logs**

```kql
// IIS log format (W3C):
// 2025-10-23 10:30:15 GET /api/users 200 0.5 203.0.113.50

CustomIISLog_CL
| extend ParsedFields = split(RawData_s, ' ')
| extend 
    Date = tostring(ParsedFields[0]),
    Time = tostring(ParsedFields[1]),
    Method = tostring(ParsedFields[2]),
    URI = tostring(ParsedFields[3]),
    StatusCode = toint(ParsedFields[4]),
    ResponseTime = todouble(ParsedFields[5]),
    ClientIP = tostring(ParsedFields[6])
| extend Timestamp = todatetime(strcat(Date, ' ', Time))
| project Timestamp, Method, URI, StatusCode, ResponseTime, ClientIP
```

**Example 2: Parse JSON Logs**

```kql
// JSON log format:
// {"timestamp": "2025-10-23T10:30:15Z", "user": "john@contoso.com", "action": "login", "result": "success"}

CustomAppLog_CL
| extend JsonParsed = parse_json(RawData_s)
| extend
    Timestamp = todatetime(JsonParsed.timestamp),
    User = tostring(JsonParsed.user),
    Action = tostring(JsonParsed.action),
    Result = tostring(JsonParsed.result)
| project Timestamp, User, Action, Result
```

**Example 3: Create Function for Reusability**

```kql
// Save as function: ParseIISLogs()

let ParseIISLogs = () {
    CustomIISLog_CL
    | extend ParsedFields = split(RawData_s, ' ')
    | extend 
        Date = tostring(ParsedFields[0]),
        Time = tostring(ParsedFields[1]),
        Method = tostring(ParsedFields[2]),
        URI = tostring(ParsedFields[3]),
        StatusCode = toint(ParsedFields[4]),
        ResponseTime = todouble(ParsedFields[5]),
        ClientIP = tostring(ParsedFields[6])
    | extend Timestamp = todatetime(strcat(Date, ' ', Time))
    | project Timestamp, Method, URI, StatusCode, ResponseTime, ClientIP
};

// Usage in analytics rules:
ParseIISLogs()
| where StatusCode >= 400  // Client/server errors
| where ResponseTime > 5  // Slow responses (>5 sec)
| summarize count() by URI, StatusCode
```

**🎯 Exam Tip:**
- **Custom logs** = Any data not covered by built-in connectors
- **HTTP Data Collector API** = REST API for custom log ingestion
- **Table naming**: Name_CL (suffix _CL automatically added)
- **Field types**: _s (string), _d (double), _b (boolean), _t (datetime), _g (GUID)
- **Parsing**: use parse_json(), split(), extract() for structured data
- **Functions**: Save parsed queries as functions for reusability

---

## 7. Threat Intelligence Integration

### 7.1 Threat Intelligence Overview

**What is Threat Intelligence (TI)?**

```
Definition: Information about threats, threat actors, and indicators of compromise (IoCs)

Types of Threat Intelligence:

1️⃣ Strategic TI (High-Level)
   ├─ Audience: Executives, board members
   ├─ Content: Threat landscape trends, geopolitical risks
   ├─ Use: Business decisions, risk assessment
   └─ Example: "Ransomware attacks increased 200% in Q3"

2️⃣ Tactical TI (Mid-Level)
   ├─ Audience: Security architects, SOC managers
   ├─ Content: TTPs (Tactics, Techniques, Procedures)
   ├─ Use: Detection strategy, security architecture
   └─ Example: "APT28 uses spear-phishing with macro-enabled docs"

3️⃣ Operational TI (Action-Oriented)
   ├─ Audience: SOC analysts, incident responders
   ├─ Content: Specific threats, attack campaigns
   ├─ Use: Current threat awareness, incident response
   └─ Example: "CVE-2025-1234 actively exploited in the wild"

4️⃣ Technical TI (IoCs - Indicators of Compromise)
   ├─ Audience: Security tools, SIEM, EDR, firewalls
   ├─ Content: IPs, domains, file hashes, URLs
   ├─ Use: Automated detection, blocking
   └─ Example: "IP 203.0.113.50 associated with Emotet C2"
```

### 7.2 Threat Intelligence in Sentinel

**🆕 July 2025: New Threat Intelligence Tables (STIX 2.1)**

```
Major Update: Sentinel TI Architecture Revamp

Old (Legacy):
└─ ThreatIntelligenceIndicator (single table, limited schema)

🆕 New (2025):
├─ ThreatIntelIndicators (STIX 2.1 indicators)
└─ ThreatIntelObjects (relationships, threat actors, attack patterns)

🆕 STIX 2.1 Support:
- Structured Threat Information eXpression (STIX)
- Industry standard for threat intel sharing
- Richer data model: Relationships, context, confidence

Migration Timeline:
├─ Now: Both old and new tables populated (dual write)
├─ July 31, 2025: Deadline to migrate queries, rules, workbooks
└─ August 1, 2025: Legacy table (ThreatIntelligenceIndicator) deprecated

Action Required:
⚠️ Update custom queries, analytics rules, workbooks to use new tables
⚠️ Test before July 31, 2025 to avoid disruption
```

**ThreatIntelIndicators Table (New):**

```kql
// View schema
ThreatIntelIndicators
| getschema

Key Columns:
├─ TimeGenerated: Ingestion time
├─ IndicatorId: Unique identifier (GUID)
├─ ThreatType: malware, botnet, phishing, etc.
├─ ConfidenceScore: 0-100 (confidence in indicator)
├─ Active: true/false (is indicator still active?)
├─ ExpirationDateTime: When indicator expires
├─ Description: Threat description
├─ ThreatSeverity: 0-5 (severity scale)
│
├─ IoC Fields (Indicator of Compromise):
│  ├─ NetworkIP: IP address
│  ├─ NetworkDestinationIP: Destination IP
│  ├─ Url: URL
│  ├─ DomainName: Domain
│  ├─ EmailSourceDomain: Email domain
│  ├─ EmailSourceIpAddress: Email server IP
│  ├─ FileHashValue: File hash (MD5, SHA1, SHA256)
│  └─ FileHashType: Hash algorithm
│
├─ Source Information:
│  ├─ SourceSystem: Microsoft Defender TI, TAXII, etc.
│  ├─ Tags: Custom tags (APT28, ransomware, etc.)
│  └─ AdditionalInformation: JSON with extra context
│
└─ 🆕 STIX Fields:
   ├─ StixId: STIX object ID
   ├─ PatternType: STIX pattern type
   └─ Pattern: STIX pattern (e.g., IPv4 address)

Example Query (Find threats in network logs):
ThreatIntelIndicators
| where Active == true
| where NetworkIP != ""
| join kind=inner (
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
  ) on $left.NetworkIP == $right.DestinationIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, Description
```

**ThreatIntelObjects Table (New - Relationships):**

```kql
// View schema
ThreatIntelObjects
| getschema

Key Columns:
├─ TimeGenerated: Ingestion time
├─ ObjectId: Unique identifier (STIX ID)
├─ ObjectType: threat-actor, attack-pattern, malware, tool, etc.
├─ Name: Object name (e.g., "APT28", "Mimikatz")
├─ Description: Detailed description
├─ Created: Creation timestamp
├─ Modified: Last modified timestamp
│
├─ 🆕 Relationship Support:
│  ├─ SourceRef: Source object ID
│  ├─ TargetRef: Target object ID
│  ├─ RelationshipType: uses, targets, attributed-to, etc.
│  └─ Example: "APT28 uses Mimikatz"
│
└─ Additional Fields: JSON with full STIX 2.1 object

Example Query (Find attack patterns used by threat actor):
ThreatIntelObjects
| where ObjectType == "relationship"
| where SourceRef contains "threat-actor--APT28"
| where RelationshipType == "uses"
| join kind=inner (
    ThreatIntelObjects
    | where ObjectType == "attack-pattern"
  ) on $left.TargetRef == $right.ObjectId
| project ThreatActor = "APT28", AttackPattern = Name, Description
```

### 7.3 Threat Intelligence Sources

**Built-in TI Sources:**

```
🆕 Microsoft Defender Threat Intelligence (MDTI) - FREE (July 2025)
├─ Previously: $10K+/year (expensive!)
├─ 🆕 Now: FREE for all Sentinel + Defender XDR customers
├─ Content:
│  ├─ 84 trillion daily signals (Microsoft global visibility)
│  ├─ 10,000+ security professionals' analysis
│  ├─ Threat actor profiles (APT groups, ransomware gangs)
│  ├─ Vulnerability intelligence (CVEs, exploits)
│  ├─ IoC feeds (IPs, domains, file hashes) - real-time updates
│  └─ Attack tooling analysis (malware, exploits)
│
├─ Rollout: Phase 1 by October 2025, complete by H1 2026
├─ Integration: Auto-ingested into ThreatIntelIndicators/Objects tables
└─ 🆕 Bi-directional export: Export TI back to TAXII servers (2025)

Microsoft Threat Intelligence (Legacy - Being Replaced by MDTI)
├─ Source: Microsoft Security Response Center (MSRC)
├─ Content: CVEs, security updates, threat actors
└─ Note: Converging into MDTI (unified experience)

Third-Party TI Platforms (Partner Ecosystem):
├─ Commercial: Recorded Future, Anomali, ThreatConnect, CrowdStrike
├─ Open-source: AlienVault OTX, MISP, Abuse.ch, VirusTotal
├─ Community: ISACs, CERTs, government feeds
└─ Integration: TAXII 2.x, STIX 2.1, upload API, connectors
```

### 7.4 TAXII Connector

**Trusted Automated eXchange of Intelligence Information (TAXII):**

```
What is TAXII?
- Protocol for exchanging threat intelligence
- Standard: TAXII 2.0, TAXII 2.1 (latest)
- Format: STIX (Structured Threat Information eXpression)

TAXII Architecture:
TI Platform (TAXII Server) → Sentinel (TAXII Client)

Configuration Steps:

Step 1: Get TAXII Server Details
─────────────────────────────────────────
From TI provider (e.g., AlienVault OTX, Anomali):
├─ API Root URL: https://otx.alienvault.com/taxii/
├─ Collection ID: collection-12345
├─ Username/API Key: (authentication)
└─ Poll interval: How often to fetch (1 hour, 1 day, etc.)

Step 2: Configure TAXII Connector in Sentinel
─────────────────────────────────────────
Azure Portal → Sentinel → Data connectors → Threat Intelligence - TAXII

Configuration:
├─ Friendly name: AlienVault OTX
├─ API root URL: https://otx.alienvault.com/taxii/
├─ Collection ID: collection-12345
├─ Username: your-username
├─ Password/API Key: your-api-key
├─ Import indicators from: 30 days ago (initial load)
└─ Poll frequency: Once an hour (recommended)

Step 3: Verify Ingestion
─────────────────────────────────────────
Wait: 5-10 minutes for first indicators

Query:
ThreatIntelIndicators
| where SourceSystem contains "TAXII"
| where Active == true
| summarize count() by ThreatType
| render columnchart

Expected: Indicators appearing with SourceSystem = "TAXII - AlienVault OTX"

Step 4: 🆕 Bi-Directional Export (2025)
─────────────────────────────────────────
New Feature: Export TI from Sentinel back to TAXII servers

Use Case: Share threat intel with partners, community

Configuration:
1. Sentinel → Threat Intelligence → Export
2. Select indicators to export (custom queries)
3. Configure TAXII 2.1 server (destination)
4. Export: Manual or scheduled

Example: Export malicious IPs detected in your environment
ThreatIntelIndicators
| where ThreatType == "botnet"
| where SourceSystem == "Sentinel - Custom Detection"
| where ConfidenceScore > 80
```

### 7.5 STIX Indicator Upload

**Manual Indicator Upload (STIX Format):**

```
Use Case: Upload custom IoCs (from incident response, threat intel reports)

STIX Bundle Example (JSON):
{
  "type": "bundle",
  "id": "bundle--12345",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--67890",
      "created": "2025-10-23T10:00:00.000Z",
      "modified": "2025-10-23T10:00:00.000Z",
      "name": "Malicious IP from phishing campaign",
      "pattern": "[ipv4-addr:value = '203.0.113.50']",
      "pattern_type": "stix",
      "valid_from": "2025-10-23T10:00:00.000Z",
      "valid_until": "2025-12-31T23:59:59.000Z",
      "labels": ["malicious-activity", "phishing"]
    },
    {
      "type": "indicator",
      "id": "indicator--11111",
      "created": "2025-10-23T10:00:00.000Z",
      "modified": "2025-10-23T10:00:00.000Z",
      "name": "Emotet C2 domain",
      "pattern": "[domain-name:value = 'evil.com']",
      "pattern_type": "stix",
      "valid_from": "2025-10-23T10:00:00.000Z",
      "valid_until": "2025-12-31T23:59:59.000Z",
      "labels": ["malicious-activity", "emotet", "c2"]
    }
  ]
}

Upload Methods:

1️⃣ Azure Portal (Manual)
   - Sentinel → Threat Intelligence → Upload indicators
   - Select STIX JSON file
   - Upload (batch upload: up to 10,000 indicators)

2️⃣ Upload Indicators API (Programmatic)
   - REST API endpoint: https://management.azure.com/.../uploadIndicators
   - Use for: Automation, integration with custom tools
   - Example: Upload IoCs from incident response tool

3️⃣ Logic Apps (Scheduled Upload)
   - Use: Automated periodic uploads
   - Trigger: Schedule (daily, weekly)
   - Action: HTTP request to upload API
   - Source: TI platform, custom database, CSV file
```

### 7.6 Threat Intelligence Matching

**Correlating TI with Logs:**

```kql
// Example 1: Match malicious IPs in firewall logs

// Step 1: Get active malicious IPs from TI
let MaliciousIPs = ThreatIntelIndicators
| where Active == true
| where NetworkIP != ""
| where ConfidenceScore > 70  // High confidence only
| distinct NetworkIP;

// Step 2: Find matches in firewall logs
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationIP in (MaliciousIPs)
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction
| join kind=inner (ThreatIntelIndicators) on $left.DestinationIP == $right.NetworkIP
| project 
    TimeGenerated, 
    SourceIP, 
    DestinationIP, 
    ThreatType, 
    Description, 
    ConfidenceScore,
    DeviceAction
| order by TimeGenerated desc

// Result: All connections to known malicious IPs

────────────────────────────────────────────────────────────

// Example 2: Match malicious domains in DNS logs

let MaliciousDomains = ThreatIntelIndicators
| where Active == true
| where DomainName != ""
| distinct DomainName;

DnsEvents
| where TimeGenerated > ago(1d)
| where Name in (MaliciousDomains)
| join kind=inner (ThreatIntelIndicators) on $left.Name == $right.DomainName
| project 
    TimeGenerated, 
    ClientIP, 
    Name, 
    ThreatType, 
    Description

────────────────────────────────────────────────────────────

// Example 3: Match file hashes (malware detection)

let MaliciousHashes = ThreatIntelIndicators
| where Active == true
| where FileHashValue != ""
| distinct FileHashValue;

DeviceFileEvents  // MDE table
| where TimeGenerated > ago(1d)
| where SHA256 in (MaliciousHashes)
| join kind=inner (ThreatIntelIndicators) on $left.SHA256 == $right.FileHashValue
| project 
    TimeGenerated, 
    DeviceName, 
    FileName, 
    FolderPath, 
    SHA256, 
    ThreatType, 
    Description
```

**Built-in TI Matching (Fusion Rule):**

```
Fusion Rule: Advanced multi-stage attack detection

How It Works:
1. Correlates TI with multiple data sources (automatic)
2. Detects attack chains:
   - TI indicator (malicious IP) + User sign-in
   - Followed by: Unusual file download
   - Followed by: Lateral movement
3. Creates incident (not just alert) - high fidelity

Configuration:
- Sentinel → Analytics → Fusion (ML-powered)
- Enable: Enabled by default (no configuration needed)
- Tuning: Adjust sensitivity (low, medium, high)

Example Fusion Scenario:
1. User signs in from malicious IP (TI match)
2. User downloads unusual file from SharePoint
3. User accesses 50 other user accounts (lateral movement)
4. Fusion creates incident: "Multi-stage attack detected"

Benefit:
✅ Reduces false positives (correlates multiple weak signals)
✅ Detects advanced attacks (single indicators may be benign)
✅ High fidelity (Fusion incidents usually true positives)
```

**🎯 Exam Tip:**
- 🆕 **New TI tables** (2025): ThreatIntelIndicators (STIX 2.1 indicators), ThreatIntelObjects (relationships, threat actors)
- 🆕 **Migration deadline**: July 31, 2025 (legacy table deprecated)
- 🆕 **MDTI FREE** (July 2025): Microsoft Defender Threat Intelligence included with Sentinel/Defender XDR
- **TAXII**: Protocol for TI exchange (TAXII 2.0/2.1), configure connector for auto-import
- **STIX**: Standard format (JSON), upload via portal or API
- 🆕 **Bi-directional export** (2025): Export TI from Sentinel to TAXII servers
- **Matching**: Join TI tables with logs (NetworkIP, DomainName, FileHashValue)
- **Fusion**: ML-powered multi-stage attack detection (correlates TI + behaviors)

---

## 8. Cost Optimization

### 8.1 Understanding Sentinel Costs

**Cost Components:**

```
Microsoft Sentinel Pricing Breakdown:

1️⃣ Data Ingestion (Pay-per-GB)
   ├─ Cost: $2.46/GB (Pay-As-You-Go)
   ├─ Free tier: First 5 GB/day per workspace (10 GB with Defender for Servers P2)
   ├─ Commitment tiers: Volume discounts
   │  ├─ 100 GB/day: $1.20/GB (51% discount)
   │  ├─ 200 GB/day: $1.10/GB (55% discount)
   │  ├─ 500 GB/day: $0.98/GB (60% discount)
   │  └─ Up to 5,000 GB/day (custom pricing)
   └─ Note: Charged once (includes Log Analytics + Sentinel)

2️⃣ Data Retention (Long-term Storage)
   ├─ First 90 days: FREE (included)
   ├─ 91-730 days: $0.10/GB/month (interactive tier)
   ├─ 🆕 Sentinel Data Lake: Lower cost (preview, pricing TBD)
   └─ Archive tier: ~$0.02/GB/month (7+ years, restore on demand)

3️⃣ Playbooks (Logic Apps)
   ├─ Per execution: ~$0.000025 per action
   ├─ Example: 1,000 playbook runs/month = $0.25/month (negligible)
   └─ Note: Included connectors (no extra cost), premium connectors may charge

4️⃣ Notebooks (Azure Machine Learning)
   ├─ Compute: Charged based on VM usage (when notebook running)
   ├─ Cost: $0.10-$1.00/hour (depending on VM size)
   └─ Recommendation: Stop compute when not in use

5️⃣ Basic Logs (Low-cost Option)
   ├─ Cost: ~$0.50/GB (80% cheaper than regular logs)
   ├─ Limitation: Limited KQL queries (no joins, aggregations)
   ├─ Use: High-volume, low-value logs (verbose logging)
   └─ Tables: Any custom table, some Azure tables

Example Monthly Cost Calculation:
─────────────────────────────────────────
Scenario: 100 GB/day ingestion

Pay-As-You-Go:
- Ingestion: 100 GB/day × 30 days × $2.46/GB = $7,380/month
- Retention (90 days): FREE
- Total: $7,380/month

Commitment Tier (100 GB/day):
- Ingestion: 100 GB/day × 30 days × $1.20/GB = $3,600/month
- Savings: $3,780/month (51% reduction!)

With Extended Retention (1 year):
- Ingestion: $3,600/month
- Retention (91-365 days): 100 GB/day × 275 days × $0.10/GB = $2,750 (one-time)
- Total: $3,600/month + $2,750 retention = $6,350 (first year)
```

### 8.2 Cost Optimization Strategies

**Strategy 1: Commitment Tiers**

```
When to Use:
✅ Predictable ingestion (>100 GB/day consistent)
✅ Long-term deployment (not pilot/PoC)

How to Enable:
1. Sentinel → Settings → Pricing
2. Select commitment tier: 100 GB/day, 200 GB/day, etc.
3. Overage: Charged at reduced rate (not Pay-As-You-Go)

Breakeven Analysis:
- 100 GB/day tier costs: 100 GB × $1.20 = $120/day
- Pay-As-You-Go costs: 100 GB × $2.46 = $246/day
- Breakeven: Always beneficial if ingesting ≥100 GB/day

Recommendation:
✅ Use commitment tier if ingestion stable and >100 GB/day
⚠️ Review quarterly (can change tier as usage changes)
```

**Strategy 2: Filter Data at Source**

```
Problem: Ingesting too much unnecessary data (noisy events)

Solution: Filter BEFORE ingestion (DCR transformations, XPath)

Example: Windows Security Events (Event ID 5156 - Windows Filtering Platform)
- Volume: 60% of all Security events (very noisy!)
- Value: Low (routine network connections)
- Action: Filter at DCR

Before Filtering:
- Ingestion: 100 GB/day Security events
- Cost: 100 GB × $2.46 = $246/day

After Filtering (Exclude Event ID 5156):
- Ingestion: 40 GB/day (60% reduction!)
- Cost: 40 GB × $2.46 = $98.40/day
- Savings: $147.60/day = $4,428/month (60% reduction!)

DCR Configuration (XPath Filter):
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID != 5156 and EventID != 5158 and EventID != 5157)]]
    </Select>
  </Query>
</QueryList>

Other Noisy Events to Consider Filtering:
├─ 5156: Windows Filtering Platform (network connections)
├─ 5158: Windows Filtering Platform (allowed connection)
├─ 5157: Windows Filtering Platform (blocked connection)
├─ 4663: Object access (if auditing too verbose)
└─ 4662: Operation performed on object (AD replication, etc.)
```

**Strategy 3: Sample High-Volume Logs**

```
Problem: High-volume logs (IIS, firewall) expensive but only need sample

Solution: Sample data (ingest only X% of logs)

Example: IIS Logs
- Volume: 500 GB/day (detailed request logs)
- Cost: 500 GB × $2.46 = $1,230/day
- Need: Threat detection (not every single request)

Solution: Sample 10% (sufficient for pattern detection)
- Ingestion: 50 GB/day (90% reduction!)
- Cost: 50 GB × $2.46 = $123/day
- Savings: $1,107/day = $33,210/month

Implementation (DCR Transformation):
source
| where rand() < 0.1  // Sample 10% randomly
| project TimeGenerated, ClientIP, URI, StatusCode, UserAgent

⚠️ Considerations:
- Works well for: Pattern detection, anomaly detection
- NOT suitable for: Compliance (need 100% logs), forensics
- Recommendation: Sample non-compliance logs, keep compliance logs at 100%
```

**Strategy 4: Basic Logs (Low-Cost Tier)**

```
🆕 Feature: Basic Logs (80% cost reduction)

What: Lower-cost ingestion tier with limited query capabilities

Cost:
- Regular logs: $2.46/GB
- Basic logs: ~$0.50/GB (80% cheaper!)

Limitations:
❌ No joins (cannot join with other tables)
❌ No aggregations (summarize, count, avg, etc.)
❌ No functions (parse_json, extract, etc.)
✅ Simple filtering only (where, project, take)

When to Use:
✅ High-volume, low-value logs (verbose application logs)
✅ Logs rarely queried (archive, compliance)
✅ Logs used only for specific incident investigation (not analytics)

Example: IIS Logs (500 GB/day)
- Regular logs: 500 GB × $2.46 = $1,230/day
- Basic logs: 500 GB × $0.50 = $250/day
- Savings: $980/day = $29,400/month (80%!)

Configuration:
1. Azure Portal → Log Analytics workspace → Tables
2. Select table: CustomIISLog_CL
3. Change tier: Basic logs
4. Confirm: Data plan changed

Query Limitations Example:
✅ Allowed:
CustomIISLog_CL
| where StatusCode >= 400
| take 100

❌ Not Allowed:
CustomIISLog_CL
| where StatusCode >= 400
| summarize count() by URI  // Aggregation not supported
| join kind=inner (ThreatIntelIndicators) on $left.ClientIP == $right.NetworkIP  // Join not supported

Workaround: If need analytics, restore from archive to analytics logs (temporary)
```

**Strategy 5: 🆕 Sentinel Data Lake (Preview - July 2025)**

```
🆕 Cost-Effective Long-Term Retention

What: New storage tier for cold data (rarely accessed)

Cost:
- Hot tier (interactive): $0.10/GB/month (after 90 days)
- 🆕 Data Lake: Lower cost (pricing TBD, estimated ~$0.03-$0.05/GB/month)
- Archive tier: ~$0.02/GB/month (restore required)

Comparison:
┌────────────────────────────────────────────────────────┐
│ Tier       | Cost/GB/mo | Query | Use Case            │
├────────────────────────────────────────────────────────┤
│ Hot        | $0.10      | Fast  | Active data (90-730d)│
│ Data Lake  | ~$0.04     | Good  | Cold data (compliance)│
│ Archive    | $0.02      | Slow  | Rarely accessed (7y+)│
└────────────────────────────────────────────────────────┘

When to Use:
✅ Compliance: Long-term retention (2-7 years)
✅ Cold data: Rarely accessed (not active investigations)
✅ Cost savings: 60% cheaper than hot tier

Migration Strategy:
1. Identify cold data: Logs >365 days old
2. Migrate: Hot tier → Data Lake (automated policy)
3. Query: Multi-modal analytics (KQL with limitations)
4. Restore: If need full KQL, temporarily restore to hot tier

Configuration:
1. Sentinel → Settings → Data Lake (preview)
2. Enable Data Lake
3. Select tables to migrate
4. Set policy: Move data older than X days to Data Lake

Example Savings:
Scenario: 100 GB/day, 2-year retention

Hot tier only:
- 90 days: FREE
- 91-730 days: 100 GB × 640 days × $0.10/GB = $6,400

With Data Lake:
- 90 days: FREE (hot)
- 91-365 days: 100 GB × 275 days × $0.10/GB = $2,750 (hot)
- 366-730 days: 100 GB × 365 days × $0.04/GB = $1,460 (data lake)
- Total: $4,210 (saving $2,190/year = 34%!)
```

**Strategy 6: Monitor and Optimize Usage**

```
Monitoring Tools:

1️⃣ Azure Cost Management
   - Portal: Cost Management + Billing → Cost analysis
   - Filter: Resource type = Log Analytics workspace
   - View: Daily ingestion costs, trends, forecasts
   - Alerts: Set budget alerts (e.g., >$5,000/month)

2️⃣ Sentinel Usage Dashboard (Built-in Workbook)
   - Sentinel → Workbooks → Usage
   - View: Ingestion by table, connector, data type
   - Identify: Top contributors (which tables ingesting most?)
   - Action: Optimize high-volume tables

3️⃣ KQL Queries for Cost Analysis
   - Query ingestion by table:
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize IngestedGB = sum(Quantity) / 1000 by DataType
| order by IngestedGB desc
| render columnchart

   - Identify noisy tables:
SecurityEvent
| where TimeGenerated > ago(1d)
| summarize count() by EventID
| order by count_ desc
| take 10  // Top 10 noisiest Event IDs

Optimization Process:
1. Identify: High-volume tables (SecurityEvent, Syslog, etc.)
2. Analyze: Is all this data needed? (filtering opportunity?)
3. Optimize: Apply filters, sampling, Basic Logs
4. Monitor: Track ingestion reduction
5. Iterate: Continuous optimization (quarterly reviews)

Typical Optimization Results:
- 30-50% cost reduction (filtering noisy events)
- 60-80% reduction (Basic Logs for verbose logs)
- ROI: Optimization effort pays for itself in 1-2 months
```

**Best Practices Summary:**

```
Cost Optimization Checklist:

✅ 1. Use commitment tier (if >100 GB/day)
✅ 2. Filter noisy events at source (DCR, XPath)
✅ 3. Sample high-volume logs (10-20% sampling)
✅ 4. Use Basic Logs for verbose, low-value logs
✅ 5. 🆕 Migrate cold data to Data Lake (preview)
✅ 6. Archive old logs (7+ years for compliance)
✅ 7. Monitor usage monthly (identify optimization opportunities)
✅ 8. Review data sources quarterly (disable unused connectors)
✅ 9. Tune analytics rules (reduce false positives = less investigation time)
✅ 10. Educate teams (awareness of cost-effective practices)

Expected Savings:
- Tier + filtering: 50-70% cost reduction
- Basic Logs: Additional 50-80% on applicable logs
- Data Lake: 30-60% on long-term retention
- Total: 60-85% overall cost reduction achievable!
```

**🎯 Exam Tip:**
- **Pricing**: $2.46/GB (Pay-As-You-Go), commitment tiers (51-60% discount)
- **Free tier**: First 5 GB/day per workspace (10 GB with Defender for Servers P2)
- **Retention**: 90 days free, $0.10/GB/month after (hot tier)
- **Optimization strategies**: Commitment tier, filter at source (DCR), sampling, Basic Logs (80% cheaper), 🆕 Data Lake (60% cheaper)
- **Monitoring**: Azure Cost Management, Usage workbook, KQL queries (Usage table)
- **Best practice**: Filter noisy Event IDs (5156, 5158, 5157, 4663, 4662)
- **Basic Logs**: Limited queries (no joins, aggregations), 80% cost savings
- 🆕 **Sentinel Data Lake** (July 2025): Cost-effective long-term retention, multi-modal analytics

---

**🎉 END OF MODULE 5 PART 2! 🎉**

You've completed **Sections 4.3-8** covering:
- ✅ Agent-Based Connectors (AMA, Windows Security Events, Linux Syslog)
- ✅ Syslog/CEF Connectors (Network devices, Linux forwarder, CEF parsing)
- ✅ Data Collection Rules (DCR architecture, filtering, transformations)
- ✅ Custom Log Tables (HTTP Data Collector API, schema design, parsing)
- ✅ 🆕 Threat Intelligence (2025 updates: ThreatIntelIndicators/Objects, MDTI FREE, bi-directional export)
- ✅ Cost Optimization (commitment tiers, filtering, sampling, Basic Logs, 🆕 Data Lake)

**Progress: Module 5 Part 2 of 6 complete!**

**Coming in Part 3:**
- Analytics Rules (Scheduled, NRT, Anomaly, Fusion, Microsoft Security)
- Entity Mapping and MITRE ATT&CK
- ASIM Parsers (Advanced Security Information Model)
- Rule Tuning and Optimization

**Continue to Part 3?** 🚀
